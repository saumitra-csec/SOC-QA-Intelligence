#!/usr/bin/env python3
"""
Load a generated SOC triage events file into SOC-QA Intelligence and score the platform against the
answer key.

Pipeline (same services the API uses): ingest -> normalize -> data quality -> register cases ->
associate analyst activities -> conformance replay -> compare with ground truth.

Ingestion alone does not create cases, and conformance needs a case that points at a playbook, so
this script registers one case per case_id found in the events (playbook taken from the events).

Usage (from repo root):
    PYTHONPATH=. python3 scripts/run_triage_test_dataset.py \
        --events soc_triage_test_events.json --key soc_triage_test_events_ground_truth.json

    --temp-db     run against a throwaway SQLite file instead of data/socqa_research.db
    --stqs        also compute the Standardized Triage Quality Scale for every case
    --ingest-key  also ingest the answer key as a ground_truth_annotations dataset
"""
import argparse
import json
import os
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--events", required=True)
    ap.add_argument("--key", default=None)
    ap.add_argument("--temp-db", action="store_true")
    ap.add_argument("--stqs", action="store_true")
    ap.add_argument("--ingest-key", action="store_true")
    ap.add_argument("--show-mismatches", type=int, default=15)
    args = ap.parse_args()

    tmp = None
    if args.temp_db:
        tmp = tempfile.TemporaryDirectory()
        os.environ["SQLITE_FALLBACK_PATH"] = str(Path(tmp.name) / "triage_test.db")
        os.environ["RAW_STORAGE_DIR"] = str(Path(tmp.name) / "raw")
        os.environ["NORMALIZED_STORAGE_DIR"] = str(Path(tmp.name) / "normalized")
        os.environ["EXPORT_STORAGE_DIR"] = str(Path(tmp.name) / "exports")

    from backend.app.core.database import db_manager
    from backend.app.services.cases.manager import associate_records_by_explicit_rule, create_or_update_case
    from backend.app.services.ingestion.parser import ingest_dataset_file
    from backend.app.services.normalization.engine import normalize_dataset
    from backend.app.services.process_mining.benchmark_evaluator import ensure_reference_playbooks_loaded
    from backend.app.services.process_mining.contracts import pm4py_service
    from backend.app.services.validation.quality import evaluate_dataset_quality

    ev_path = Path(args.events)
    content = ev_path.read_bytes()

    # 1. playbooks must be present before conformance can run
    ensure_reference_playbooks_loaded()

    # 2. ingest (raw file preserved, SHA-256 recorded)
    ing = ingest_dataset_file(
        filename=ev_path.name, content=content, category="analyst_activity_logs",
        dataset_name=f"SOC Triage Test Events ({ev_path.name})", source_organization="Synthetic SOC Triage Generator",
        license_info="Synthetic test data",
    )
    s = ing["summary"]
    print(f"[ingest]    {ing['dataset_id']}  records={s['total_records']}  accepted={s['accepted_count']}  "
          f"rejected={s['rejected_count']}  duplicates={s['duplicate_count']}  warnings={s['warning_count']}")
    if ing["inspection"]["missing_expected_fields"]:
        print("            missing expected fields:", ing["inspection"]["missing_expected_fields"])

    # 3. normalize with an identity mapping (field names are already canonical)
    norm = normalize_dataset(ing["dataset_id"], "analyst_activity", {})
    ts = norm["timestamp_summary"]
    print(f"[normalize] normalized={norm['normalized_count']}  utc_ok={ts['valid_utc_or_converted']}  "
          f"ambiguous_flagged={ts['ambiguous_flagged_for_review']}  invalid={ts['invalid_or_missing']}  "
          f"unsupported_targets={norm['unsupported_mapping_targets']}")

    # 4. data quality
    q = evaluate_dataset_quality(ing["dataset_id"])
    print(f"[quality]   readiness={q.get('readiness_status')}")

    # 5. register cases from the events and link activities
    cases = {}
    for rec in _records(content, ev_path.suffix.lower()):
        c = cases.setdefault(rec["case_id"], {"type": rec["incident_type"], "pb": rec["playbook_id"],
                                              "ver": rec["playbook_version"], "closed": None})
        st = (rec.get("activity_status") or "")
        if st.startswith("closed_"):
            c["closed"] = st
    for cid, c in cases.items():
        create_or_update_case(
            case_id=cid, incident_category=c["type"], case_status=c["closed"] or "open",
            playbook_id=c["pb"], playbook_version=c["ver"], dataset_source_id=ing["dataset_id"],
            data_quality_status="Valid", summary=f"Synthetic triage case ({c['type']})",
        )
        associate_records_by_explicit_rule(cid, "case_id")
    print(f"[cases]     registered={len(cases)}  (open={sum(1 for c in cases.values() if not c['closed'])})")

    # 6. conformance replay
    results = {}
    for cid in cases:
        results[cid] = pm4py_service.check_conformance_alignments(cid)
    flagged = sum(1 for r in results.values() if not r["is_conformant"])
    print(f"[conform]   engine={next(iter(results.values()))['conformance_engine']}  "
          f"flagged_deviating={flagged}/{len(results)}")

    if args.stqs:
        stqs = pm4py_service.evaluate_all_cases_standardized_triage_scale()
        print(f"[stqs]      evaluated={stqs['total_cases_evaluated']} cases  bands={stqs['band_distribution']}")

    if args.key:
        key = json.loads(Path(args.key).read_text(encoding="utf-8"))["records"]
        if args.ingest_key:
            kd = ingest_dataset_file(Path(args.key).name, Path(args.key).read_bytes(), "ground_truth_annotations",
                                     dataset_name="SOC Triage Test Answer Key", license_info="Synthetic test data")
            print(f"[key]       ingested {kd['dataset_id']} ({kd['summary']['total_records']} rows)")
        report(key, results, args.show_mismatches)

    if tmp:
        tmp.cleanup()


def _records(content: bytes, suffix: str):
    text = content.decode("utf-8")
    if suffix == ".json":
        d = json.loads(text)
        return d["records"] if isinstance(d, dict) else d
    if suffix in (".jsonl", ".ndjson"):
        return [json.loads(l) for l in text.splitlines() if l.strip()]
    import csv, io
    return list(csv.DictReader(io.StringIO(text)))


def report(key, results, show):
    tp = tn = fp = fn = 0
    mism = []
    by_type = defaultdict(lambda: Counter())
    for k in key:
        cid = k["case_id"]
        r = results.get(cid)
        if r is None:
            continue
        truth_dev = k["conformance_class"] == "deviating"
        pred_dev = not r["is_conformant"]
        if truth_dev and pred_dev: tp += 1
        elif not truth_dev and not pred_dev: tn += 1
        elif pred_dev: fp += 1
        else: fn += 1
        ok = truth_dev == pred_dev
        by_type[k["incident_category"]]["ok" if ok else "miss"] += 1
        if not ok:
            mism.append((cid, k, r))
    n = tp + tn + fp + fn
    prec = tp / max(tp + fp, 1)
    rec = tp / max(tp + fn, 1)
    print("\n=== Platform vs answer key ===")
    print(f"cases scored: {n}    accuracy: {(tp + tn) / max(n, 1):.1%}")
    print(f"confusion:    TP={tp} (deviation caught)  TN={tn}  FP={fp} (conformant case flagged)  FN={fn} (deviation missed)")
    print(f"deviation precision={prec:.3f}  recall={rec:.3f}  F1={2 * prec * rec / max(prec + rec, 1e-9):.3f}")
    if mism:
        print(f"\nmismatches ({len(mism)}):")
        for cid, k, r in mism[:show]:
            why = k["known_confounder"] or k["scenario"]
            print(f"  {cid}  truth={k['conformance_class']:<10} platform={'deviating' if not r['is_conformant'] else 'conformant':<10} "
                  f"[{why}]  trace={' > '.join(r['observed_trace'])}")


if __name__ == "__main__":
    main()
