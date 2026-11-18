"""
75-Case Controlled Benchmark Generator & Empirical Hypothesis Evaluation Engine.
Populates 25 Phishing, 25 Password Spraying (T1110.003), and 25 Suspicious PowerShell (T1059.001)
cases (45 Conformant, 30 Deviating = 75 Total) with isolated ground_truth_labels, locked reference
Petri nets, and reproducible empirical evaluation metrics.
"""
import json
import uuid
from pathlib import Path
from typing import Any, Dict, List, Tuple

from backend.app.core.config import ROOT_DIR
from backend.app.core.database import db_manager, utc_now_iso
from backend.app.services.playbooks.repository import (
    import_playbook_csv,
    import_playbook_json,
    list_playbooks,
)
from backend.app.services.process_mining.contracts import pm4py_service
from backend.app.services.ai.contracts import ai_service

STRATA_SPECS = [
    {
        "incident_type": "phishing",
        "prefix": "PHISH",
        "playbook_id": "PB-PHISH-001",
        "playbook_version": "1.0",
        "mandatory_steps": [
            ("PHISH-S1", "Ingest & Parse Email Headers"),
            ("PHISH-S2", "Inspect Embedded URLs & Attachments"),
            ("PHISH-S3", "Query SIEM for Recipient Click & Post-Delivery Activity"),
            ("PHISH-S5", "Record Final Disposition & Close Case"),
        ],
        "conditional_step": ("PHISH-S4", "Isolate Compromised Account & Escalate to Tier 2"),
        "full_ordered_steps": [
            ("PHISH-S1", "Ingest & Parse Email Headers"),
            ("PHISH-S2", "Inspect Embedded URLs & Attachments"),
            ("PHISH-S3", "Query SIEM for Recipient Click & Post-Delivery Activity"),
            ("PHISH-S4", "Isolate Compromised Account & Escalate to Tier 2"),
            ("PHISH-S5", "Record Final Disposition & Close Case"),
        ],
    },
    {
        "incident_type": "password_spraying",
        "prefix": "SPRAY",
        "playbook_id": "PB-SPRAY-001",
        "playbook_version": "1.0",
        "mandatory_steps": [
            ("SPRAY-S1", "Aggregate Failed Logons by Source IP"),
            ("SPRAY-S2", "Check Subsequent Successful Logons (Event 4624 / Azure AD)"),
            ("SPRAY-S3", "Enrich Source IP & User-Agent Context"),
            ("SPRAY-S5", "Document Triage Outcome & Close Investigation"),
        ],
        "conditional_step": ("SPRAY-S4", "Reset Breached Account & Escalate to Incident Response"),
        "full_ordered_steps": [
            ("SPRAY-S1", "Aggregate Failed Logons by Source IP"),
            ("SPRAY-S2", "Check Subsequent Successful Logons (Event 4624 / Azure AD)"),
            ("SPRAY-S3", "Enrich Source IP & User-Agent Context"),
            ("SPRAY-S4", "Reset Breached Account & Escalate to Incident Response"),
            ("SPRAY-S5", "Document Triage Outcome & Close Investigation"),
        ],
    },
    {
        "incident_type": "suspicious_powershell",
        "prefix": "PSH",
        "playbook_id": "PB-PSH-001",
        "playbook_version": "1.0",
        "mandatory_steps": [
            ("PSH-S1", "Inspect Process Tree & Parent Image"),
            ("PSH-S2", "Retrieve & Decode Script Block Text (Event ID 4104)"),
            ("PSH-S3", "Correlate Outbound Network & File Creation Indicators"),
            ("PSH-S5", "Validate Administrative Legitimacy or Close Case"),
        ],
        "conditional_step": ("PSH-S4", "Isolate Endpoint & Escalate Malicious Execution"),
        "full_ordered_steps": [
            ("PSH-S1", "Inspect Process Tree & Parent Image"),
            ("PSH-S2", "Retrieve & Decode Script Block Text (Event ID 4104)"),
            ("PSH-S3", "Correlate Outbound Network & File Creation Indicators"),
            ("PSH-S4", "Isolate Endpoint & Escalate Malicious Execution"),
            ("PSH-S5", "Validate Administrative Legitimacy or Close Case"),
        ],
    },
]



PERSIST_STRATUM_SPEC = {
    "incident_type": "persistence_antiforensics",
    "prefix": "PERSIST",
    "playbook_id": "PB-PERSIST-001",
    "playbook_version": "1.0",
    "mandatory_steps": [
        ("PERSIST-S1", "Inspect New Windows Service Creation (Event ID 4697)"),
        ("PERSIST-S2", "Audit Account Creation & Privileged Group Escalation (4720 / 4732)"),
        ("PERSIST-S3", "Assess Audit Policy Tampering & Log Clear (4719 / 1102)"),
        ("PERSIST-S4", "Isolate Host, Disable Rogue Account & Remove Malicious Service"),
        ("PERSIST-S5", "Document Timeline Reconstruction & Close Incident"),
    ],
    "conditional_step": ("PERSIST-S4", "Isolate Host, Disable Rogue Account & Remove Malicious Service"),
    "full_ordered_steps": [
        ("PERSIST-S1", "Inspect New Windows Service Creation (Event ID 4697)"),
        ("PERSIST-S2", "Audit Account Creation & Privileged Group Escalation (4720 / 4732)"),
        ("PERSIST-S3", "Assess Audit Policy Tampering & Log Clear (4719 / 1102)"),
        ("PERSIST-S4", "Isolate Host, Disable Rogue Account & Remove Malicious Service"),
        ("PERSIST-S5", "Document Timeline Reconstruction & Close Incident"),
    ],
}

def ensure_reference_playbooks_loaded():
    existing = {p["playbook_version_id"] for p in list_playbooks()}
    pb_dir = ROOT_DIR / "research" / "playbooks"
    if "PB-PHISH-001@1.0" not in existing:
        import_playbook_json((pb_dir / "PB-PHISH-001_v1.0.json").read_text(encoding="utf-8"))
    if "PB-SPRAY-001@1.0" not in existing:
        import_playbook_csv((pb_dir / "PB-SPRAY-001_v1.0.csv").read_text(encoding="utf-8"))
    if "PB-PSH-001@1.0" not in existing:
        import_playbook_json((pb_dir / "PB-PSH-001_v1.0.json").read_text(encoding="utf-8"))
    if "PB-PERSIST-001@1.0" not in existing and (pb_dir / "PB-PERSIST-001_v1.0.json").exists():
        import_playbook_json((pb_dir / "PB-PERSIST-001_v1.0.json").read_text(encoding="utf-8"))


def build_case_trace_and_ground_truth(
    spec: Dict[str, Any], idx: int
) -> Tuple[List[Tuple[str, str, bool]], str, str, int, str]:
    """
    Constructs a deterministic trace and isolated ground-truth label for case idx (1..25) within a stratum:
    - Cases 1..10: Conformant standard path (S1 -> S2 -> S3 -> S5)
    - Cases 11..13: Conformant conditional branch path (S1 -> S2 -> S3 -> S4 -> S5)
    - Cases 14..15: Conformant workflow with incomplete documentation gap (missing evidence_reference on 1 step)
    - Cases 16..18: Deviating — Single skipped mandatory step (S3 omitted)
    - Cases 19..20: Deviating — Multiple skipped mandatory steps (S2 and S3 omitted)
    - Cases 21..22: Deviating — Reordered activities (S3 executed before S2)
    - Case 23: Deviating — Repeated activity (S2 executed twice)
    - Case 24: Deviating — Additional unmapped activity inserted
    - Case 25: Deviating — Premature termination (final mandatory closure step S5 omitted)
    """
    m = spec["mandatory_steps"]
    full = spec["full_ordered_steps"]
    pfx = spec["prefix"]

    if 1 <= idx <= 10:
        steps = [(s[0], s[1], True) for s in m]
        return steps, "conformant", "none", 0, "Standard conformant mandatory workflow trace."
    if 11 <= idx <= 13:
        steps = [(s[0], s[1], True) for s in full]
        return (
            steps,
            "conformant",
            "legitimate_conditional_branch",
            1,
            "Conformant execution of conditional containment/escalation branch.",
        )
    if 14 <= idx <= 15:
        # Process is conformant, but step 2 lacks an evidence_reference (documentation/observability gap)
        steps = [
            (m[0][0], m[0][1], True),
            (m[1][0], m[1][1], False),
            (m[2][0], m[2][1], True),
            (m[3][0], m[3][1], True),
        ]
        return (
            steps,
            "conformant",
            "incomplete_documentation_gap",
            1,
            "Workflow steps are conformant; step 2 omits evidence_reference to test observability-gap separation.",
        )
    if 16 <= idx <= 18:
        # Single skipped mandatory step (S3 omitted)
        steps = [(m[0][0], m[0][1], True), (m[1][0], m[1][1], True), (m[3][0], m[3][1], True)]
        return (
            steps,
            "deviating",
            "single_skipped_step",
            0,
            f"Skipped mandatory enrichment/correlation step {m[2][0]}.",
        )
    if 19 <= idx <= 20:
        # Multiple deviations: S2 and S3 skipped
        steps = [(m[0][0], m[0][1], True), (m[3][0], m[3][1], False)]
        return (
            steps,
            "deviating",
            "multiple_deviations",
            0,
            f"Skipped multiple mandatory steps ({m[1][0]} and {m[2][0]}) and omitted closure evidence.",
        )
    if 21 <= idx <= 22:
        # Reordered steps: S1 -> S3 -> S2 -> S5
        steps = [
            (m[0][0], m[0][1], True),
            (m[2][0], m[2][1], True),
            (m[1][0], m[1][1], True),
            (m[3][0], m[3][1], True),
        ]
        return (
            steps,
            "deviating",
            "reordered_steps",
            0,
            f"Executed {m[2][0]} before its required predecessor {m[1][0]}.",
        )
    if idx == 23:
        # Repeated activity: S1 -> S2 -> S2 -> S3 -> S5
        steps = [
            (m[0][0], m[0][1], True),
            (m[1][0], m[1][1], True),
            (m[1][0], m[1][1], True),
            (m[2][0], m[2][1], True),
            (m[3][0], m[3][1], True),
        ]
        return (
            steps,
            "deviating",
            "multiple_deviations",
            0,
            f"Redundant repeated execution of {m[1][0]}.",
        )
    if idx == 24:
        # Additional unmapped activity inserted
        steps = [
            (m[0][0], m[0][1], True),
            (m[1][0], m[1][1], True),
            (f"{pfx}-UNMAPPED-99", "Ad-Hoc Unapproved External Whois Ping", False),
            (m[2][0], m[2][1], True),
            (m[3][0], m[3][1], True),
        ]
        return (
            steps,
            "deviating",
            "multiple_deviations",
            0,
            f"Introduced unmapped activity {pfx}-UNMAPPED-99 outside the reference playbook.",
        )
    # idx == 25: Premature termination (S5 closure omitted)
    steps = [(m[0][0], m[0][1], True), (m[1][0], m[1][1], True), (m[2][0], m[2][1], False)]
    return (
        steps,
        "deviating",
        "single_skipped_step",
        0,
        f"Premature termination prior to mandatory closure step {m[3][0]}.",
    )


def populate_75_case_benchmark() -> Dict[str, Any]:
    """
    Populates the 75-case controlled benchmark in the database with observed analyst traces
    and isolated ground_truth_labels.
    """
    ensure_reference_playbooks_loaded()
    now_iso = utc_now_iso()
    ds_id = "DS-BENCHMARK-75"

    with db_manager.connection() as conn:
        # Clean previous benchmark cases
        conn.execute("DELETE FROM datasets WHERE dataset_id = ?", (ds_id,))
        conn.execute("DELETE FROM cases WHERE case_id LIKE 'CASE-BM-%'")

        conn.execute(
            """
            INSERT INTO datasets (
                dataset_id, name, category, source_url, source_organization,
                dataset_version, acquisition_date, upload_date, license_info,
                processing_status, normalization_version, record_count,
                accepted_count, rejected_count, duplicate_count, warning_count
            ) VALUES (?, ?, 'analyst_activity_logs', ?, 'SOC-QA Controlled Benchmark Lab', '1.0', ?, ?, 'Academic Benchmark', 'validated', 'norm-v1.0', 0, 0, 0, 0, 0)
            """,
            (ds_id, "75-Case Controlled Experimental Benchmark", "https://pm4py.fit.fraunhofer.de/", now_iso[:10], now_iso),
        )

        total_activities = 0
        for spec in STRATA_SPECS:
            inc_type = spec["incident_type"]
            pfx = spec["prefix"]
            pb_id = spec["playbook_id"]
            pb_ver = spec["playbook_version"]

            for idx in range(1, 26):
                case_id = f"CASE-BM-{pfx}-{idx:03d}"
                steps, conf_class, dev_type, is_just, rationale = build_case_trace_and_ground_truth(
                    spec, idx
                )
                conn.execute(
                    """
                    INSERT INTO cases (
                        case_id, incident_category, case_status, playbook_id,
                        playbook_version, dataset_source_id, data_quality_status,
                        summary, created_at, updated_at
                    ) VALUES (?, ?, 'closed_true_positive', ?, ?, ?, 'Valid', ?, ?, ?)
                    """,
                    (
                        case_id,
                        inc_type,
                        pb_id,
                        pb_ver,
                        ds_id,
                        f"Controlled benchmark case ({inc_type} #{idx:02d})",
                        now_iso,
                        now_iso,
                    ),
                )

                # Store ground truth in isolated ground_truth_labels table
                conn.execute(
                    """
                    INSERT INTO ground_truth_labels (
                        label_id, case_id, benchmark_stratum, conformance_class,
                        deviation_type, is_justified_deviation, ground_truth_rationale,
                        annotated_by, annotated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'principal_researcher', ?)
                    """,
                    (
                        f"GT-{pfx}-{idx:03d}",
                        case_id,
                        inc_type,
                        conf_class,
                        dev_type,
                        is_just,
                        rationale,
                        now_iso,
                    ),
                )

                # Populate raw_records and analyst_activities WITHOUT leaking ground_truth_labels
                for s_idx, (step_id, step_name, has_evd) in enumerate(steps, start=1):
                    total_activities += 1
                    raw_id = f"RAW-BM-{pfx}-{idx:03d}-{s_idx:02d}"
                    act_id = f"ACT-BM-{pfx}-{idx:03d}-{s_idx:02d}"
                    ts_utc = f"2026-11-01T10:{s_idx * 5:02d}:00Z"
                    evd_ref = f"EVD-BM-{pfx}-{idx:03d}-{s_idx:02d}" if has_evd else None
                    raw_payload = json.dumps(
                        {
                            "case_id": case_id,
                            "activity": step_name,
                            "playbook_step_id": step_id,
                            "timestamp": ts_utc,
                            "analyst_id": f"ANL-{(idx % 5) + 1:02d}",
                        }
                    )
                    conn.execute(
                        """
                        INSERT INTO raw_records (
                            raw_record_id, dataset_id, row_index, raw_payload_json,
                            record_hash, is_malformed, is_duplicate, parse_warnings_json, ingested_at
                        ) VALUES (?, ?, ?, ?, ?, 0, 0, '[]', ?)
                        """,
                        (raw_id, ds_id, total_activities, raw_payload, f"hash-{raw_id}", now_iso),
                    )
                    conn.execute(
                        """
                        INSERT INTO analyst_activities (
                            activity_record_id, dataset_id, raw_record_id, case_id,
                            activity, original_timestamp, original_timezone,
                            normalized_utc_timestamp, timestamp_parsing_status,
                            incident_type, analyst_id, analyst_role, playbook_id,
                            playbook_version, playbook_step_id, activity_status,
                            outcome, source_system, evidence_reference,
                            timeline_category, original_fields_json, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, 'UTC', ?, 'VALID_UTC', ?, ?, 'Tier 1 SOC Analyst', ?, ?, ?, 'completed', ?, 'SOAR-Benchmark', ?, 'analyst_activity', ?, ?)
                        """,
                        (
                            act_id,
                            ds_id,
                            raw_id,
                            case_id,
                            step_name,
                            ts_utc,
                            ts_utc,
                            inc_type,
                            f"ANL-{(idx % 5) + 1:02d}",
                            pb_id,
                            pb_ver,
                            step_id,
                            ("Verified indicator artifact and recorded structured triage findings" if has_evd else "Unverified stub"),
                            evd_ref,
                            raw_payload,
                            now_iso,
                        ),
                    )

        conn.execute(
            "UPDATE datasets SET record_count = ?, accepted_count = ? WHERE dataset_id = ?",
            (total_activities, total_activities, ds_id),
        )

    return {
        "dataset_id": ds_id,
        "total_benchmark_cases": 75,
        "conformant_cases": 45,
        "deviating_cases": 30,
        "total_analyst_activities": total_activities,
    }


def run_empirical_benchmark_evaluation() -> Dict[str, Any]:
    """
    Executes the full empirical evaluation over all 75 benchmark cases:
    1. Runs PM4Py Petri-net conformance checking on each case's observed analyst trace.
    2. Runs the independent Explainable AI / Evidence-Grounded quality auditor on each case.
    3. Evaluates predictions against the isolated ground_truth_labels table.
    """
    with db_manager.connection() as conn:
        gt_rows = conn.execute(
            "SELECT * FROM ground_truth_labels WHERE case_id LIKE 'CASE-BM-%' ORDER BY case_id ASC"
        ).fetchall()

    if len(gt_rows) < 75:
        populate_75_case_benchmark()
        with db_manager.connection() as conn:
            gt_rows = conn.execute(
                "SELECT * FROM ground_truth_labels WHERE case_id LIKE 'CASE-BM-%' ORDER BY case_id ASC"
            ).fetchall()

    tp = tn = fp = fn = 0
    conformant_fitness_scores: List[float] = []
    deviating_fitness_scores: List[float] = []
    stratum_stats: Dict[str, Dict[str, int]] = {}
    deviation_type_totals = {
        "skipped_activity": 0,
        "reordered_activity": 0,
        "repeated_activity": 0,
        "additional_activity": 0,
        "premature_termination": 0,
    }
    doc_gap_cases_detected = 0
    per_case_results = []

    for gt in gt_rows:
        cid = gt["case_id"]
        stratum = gt["benchmark_stratum"]
        actual_deviating = gt["conformance_class"] == "deviating"

        conf_res = pm4py_service.check_conformance_alignments(cid)
        ai_res = ai_service.request_structured_assessment(cid)

        predicted_deviating = not conf_res["is_conformant"]
        st = stratum_stats.setdefault(
            stratum, {"total": 0, "tp": 0, "tn": 0, "fp": 0, "fn": 0}
        )
        st["total"] += 1

        if actual_deviating and predicted_deviating:
            tp += 1
            st["tp"] += 1
        elif not actual_deviating and not predicted_deviating:
            tn += 1
            st["tn"] += 1
        elif not actual_deviating and predicted_deviating:
            fp += 1
            st["fp"] += 1
        else:
            fn += 1
            st["fn"] += 1

        if actual_deviating:
            deviating_fitness_scores.append(conf_res["fitness"])
        else:
            conformant_fitness_scores.append(conf_res["fitness"])

        if conf_res["skipped_activities"]:
            deviation_type_totals["skipped_activity"] += len(conf_res["skipped_activities"])
        if conf_res["reordered_activities"]:
            deviation_type_totals["reordered_activity"] += len(conf_res["reordered_activities"])
        if conf_res["repeated_activities"]:
            deviation_type_totals["repeated_activity"] += len(conf_res["repeated_activities"])
        if conf_res["additional_activities"]:
            deviation_type_totals["additional_activity"] += len(conf_res["additional_activities"])
        if conf_res["is_premature_termination"]:
            deviation_type_totals["premature_termination"] += 1

        has_doc_gap_finding = any(
            f["finding_category"] == "documentation_quality" and f["severity"] in ("medium", "high")
            for f in ai_res["findings"]
        )
        if has_doc_gap_finding:
            doc_gap_cases_detected += 1

        per_case_results.append(
            {
                "case_id": cid,
                "stratum": stratum,
                "ground_truth_class": gt["conformance_class"],
                "ground_truth_deviation_type": gt["deviation_type"],
                "predicted_conformant": conf_res["is_conformant"],
                "fitness": conf_res["fitness"],
                "precision": conf_res["precision"],
                "skipped_activities": conf_res["skipped_activities"],
                "reordered_activities": conf_res["reordered_activities"],
                "repeated_activities": conf_res["repeated_activities"],
                "additional_activities": conf_res["additional_activities"],
                "premature_termination": conf_res["is_premature_termination"],
                "documentation_gap_flagged": has_doc_gap_finding,
            }
        )

    precision = round(tp / max(tp + fp, 1), 4)
    recall = round(tp / max(tp + fn, 1), 4)
    f1_score = round(2 * precision * recall / max(precision + recall, 1e-9), 4)
    accuracy = round((tp + tn) / max(len(gt_rows), 1), 4)
    mean_fit_conf = round(
        sum(conformant_fitness_scores) / max(len(conformant_fitness_scores), 1), 4
    )
    mean_fit_dev = round(
        sum(deviating_fitness_scores) / max(len(deviating_fitness_scores), 1), 4
    )

    exp_id = f"EXP-{uuid.uuid4().hex[:8].upper()}"
    now_iso = utc_now_iso()
    summary = {
        "experiment_id": exp_id,
        "executed_at": now_iso,
        "total_cases_evaluated": len(gt_rows),
        "confusion_matrix": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
        "metrics": {
            "precision": precision,
            "recall": recall,
            "f1_score": f1_score,
            "accuracy": accuracy,
            "mean_fitness_conformant": mean_fit_conf,
            "mean_fitness_deviating": mean_fit_dev,
            "documentation_gap_cases_isolated": doc_gap_cases_detected,
        },
        "deviation_detections_by_category": deviation_type_totals,
        "stratum_breakdown": stratum_stats,
        "sample_case_results": per_case_results[:15],
    }

    with db_manager.connection() as conn:
        conn.execute(
            """
            INSERT INTO research_experiments (
                experiment_id, experiment_name, benchmark_version,
                process_mining_config_json, ai_config_json, executed_at
            ) VALUES (?, '75-Case Playbook Drift & Conformance Evaluation', '1.0', ?, ?, ?)
            """,
            (
                exp_id,
                json.dumps({"algorithm": "petri_net_token_replay_and_alignment"}),
                json.dumps({"auditor": "socqa-evidence-auditor:v1.0-deterministic"}),
                now_iso,
            ),
        )
        for m_name, m_val in summary["metrics"].items():
            conn.execute(
                """
                INSERT INTO evaluation_metrics (
                    metric_id, experiment_id, stratum, metric_name, metric_value, computed_at
                ) VALUES (?, ?, 'all_75_cases', ?, ?, ?)
                """,
                (f"MET-{uuid.uuid4().hex[:8].upper()}", exp_id, m_name, float(m_val), now_iso),
            )

    out_report_path = ROOT_DIR / "research" / "evaluation" / "empirical_75_case_results.json"
    out_report_path.parent.mkdir(parents=True, exist_ok=True)
    out_report_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def populate_100_case_benchmark() -> Dict[str, Any]:
    """
    Populates all 100 controlled cases: 75 core cases (Phishing, Password Spraying T1110.003,
    Suspicious PowerShell T1059.001) + 25 Persistence & Anti-Forensics cases (PB-PERSIST-001).
    """
    base_res = populate_75_case_benchmark()
    ensure_reference_playbooks_loaded()
    now_iso = utc_now_iso()
    ds_id = "DS-BENCHMARK-100-PERSIST"
    spec = PERSIST_STRATUM_SPEC
    inc_type = spec["incident_type"]
    pfx = spec["prefix"]
    pb_id = spec["playbook_id"]
    pb_ver = spec["playbook_version"]

    with db_manager.connection() as conn:
        conn.execute("DELETE FROM datasets WHERE dataset_id = ?", (ds_id,))
        conn.execute("DELETE FROM cases WHERE case_id LIKE 'CASE-BM-PERSIST-%'")
        conn.execute(
            """
            INSERT INTO datasets (
                dataset_id, name, category, source_url, source_organization,
                dataset_version, acquisition_date, upload_date, license_info,
                processing_status, normalization_version, record_count,
                accepted_count, rejected_count, duplicate_count, warning_count
            ) VALUES (?, ?, 'analyst_activity_logs', ?, 'SOC-QA DFIR Benchmark Lab', '1.0', ?, ?, 'Academic Benchmark', 'validated', 'norm-v1.0', 0, 0, 0, 0, 0)
            """,
            (ds_id, "25-Case Persistence & Anti-Forensics DFIR Benchmark Track", "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon", now_iso[:10], now_iso),
        )

        total_activities = 0
        for idx in range(1, 26):
            case_id = f"CASE-BM-{pfx}-{idx:03d}"
            steps, conf_class, dev_type, is_just, rationale = build_case_trace_and_ground_truth(spec, idx)
            conn.execute(
                """
                INSERT INTO cases (
                    case_id, incident_category, case_status, playbook_id,
                    playbook_version, dataset_source_id, data_quality_status,
                    summary, created_at, updated_at
                ) VALUES (?, ?, 'closed_true_positive', ?, ?, ?, 'Valid', ?, ?, ?)
                """,
                (case_id, inc_type, pb_id, pb_ver, ds_id, f"DFIR benchmark case ({inc_type} #{idx:02d})", now_iso, now_iso),
            )
            conn.execute(
                """
                INSERT INTO ground_truth_labels (
                    label_id, case_id, benchmark_stratum, conformance_class,
                    deviation_type, is_justified_deviation, ground_truth_rationale,
                    annotated_by, annotated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'principal_researcher', ?)
                """,
                (f"GT-{pfx}-{idx:03d}", case_id, inc_type, conf_class, dev_type, is_just, rationale, now_iso),
            )
            for s_idx, (step_id, step_name, has_evd) in enumerate(steps, start=1):
                total_activities += 1
                raw_id = f"RAW-BM-{pfx}-{idx:03d}-{s_idx:02d}"
                act_id = f"ACT-BM-{pfx}-{idx:03d}-{s_idx:02d}"
                ts_utc = f"2026-11-02T11:{s_idx * 5:02d}:00Z"
                evd_ref = f"EVD-BM-{pfx}-{idx:03d}-{s_idx:02d}" if has_evd else None
                raw_payload = json.dumps({
                    "case_id": case_id,
                    "activity": step_name,
                    "playbook_step_id": step_id,
                    "timestamp": ts_utc,
                    "analyst_id": f"ANL-{(idx % 5) + 1:02d}",
                })
                conn.execute(
                    """
                    INSERT INTO raw_records (
                        raw_record_id, dataset_id, row_index, raw_payload_json,
                        record_hash, is_malformed, is_duplicate, parse_warnings_json, ingested_at
                    ) VALUES (?, ?, ?, ?, ?, 0, 0, '[]', ?)
                    """,
                    (raw_id, ds_id, total_activities, raw_payload, f"hash-{raw_id}", now_iso),
                )
                conn.execute(
                    """
                    INSERT INTO analyst_activities (
                        activity_record_id, dataset_id, raw_record_id, case_id,
                        activity, original_timestamp, original_timezone,
                        normalized_utc_timestamp, timestamp_parsing_status,
                        incident_type, analyst_id, analyst_role, playbook_id,
                        playbook_version, playbook_step_id, activity_status,
                        outcome, source_system, evidence_reference,
                        timeline_category, original_fields_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 'UTC', ?, 'VALID_UTC', ?, ?, 'Tier 2 Incident Responder', ?, ?, ?, 'completed', ?, 'DFIR-Benchmark', ?, 'analyst_activity', ?, ?)
                    """,
                    (
                        act_id, ds_id, raw_id, case_id, step_name, ts_utc, ts_utc, inc_type,
                        f"ANL-{(idx % 5) + 1:02d}", pb_id, pb_ver, step_id,
                        ("Verified DFIR artifact and recorded structured triage findings" if has_evd else "Unverified stub"),
                        evd_ref, raw_payload, now_iso,
                    ),
                )
        conn.execute(
            "UPDATE datasets SET record_count = ?, accepted_count = ? WHERE dataset_id = ?",
            (total_activities, total_activities, ds_id),
        )

    return {
        "status": "POPULATED_100_CASE_EXTENDED_BENCHMARK",
        "total_benchmark_cases": 100,
        "core_75_cases": base_res["total_benchmark_cases"],
        "auxiliary_dfir_persist_cases": 25,
        "conformant_cases": 60,
        "deviating_cases": 40,
    }


def run_100_case_empirical_evaluation() -> Dict[str, Any]:
    """
    Evaluates all 100 benchmark cases (75 Core + 25 PB-PERSIST-001 DFIR Track) against isolated
    ground_truth_labels and writes research/evaluation/empirical_100_case_results.json.
    """
    with db_manager.connection() as conn:
        cnt = conn.execute("SELECT COUNT(*) FROM cases WHERE case_id LIKE 'CASE-BM-%'").fetchone()[0]
    if cnt < 100:
        populate_100_case_benchmark()

    with db_manager.connection() as conn:
        gt_rows = conn.execute(
            "SELECT * FROM ground_truth_labels WHERE case_id LIKE 'CASE-BM-%' ORDER BY case_id ASC"
        ).fetchall()

    tp = tn = fp = fn = 0
    fit_conf, fit_dev = [], []
    stratum_stats: Dict[str, Dict[str, int]] = {}

    for gt in gt_rows:
        cid = gt["case_id"]
        strat = gt["benchmark_stratum"]
        expected_dev = gt["conformance_class"] == "deviating"
        conf = pm4py_service.check_conformance_alignments(cid)
        predicted_dev = not conf["is_conformant"]

        st = stratum_stats.setdefault(strat, {"tp": 0, "tn": 0, "fp": 0, "fn": 0, "total": 0})
        st["total"] += 1
        if expected_dev and predicted_dev:
            tp += 1; st["tp"] += 1
        elif not expected_dev and not predicted_dev:
            tn += 1; st["tn"] += 1
        elif not expected_dev and predicted_dev:
            fp += 1; st["fp"] += 1
        else:
            fn += 1; st["fn"] += 1

        if expected_dev:
            fit_dev.append(conf["fitness"])
        else:
            fit_conf.append(conf["fitness"])

    prec = round(tp / max(tp + fp, 1), 4)
    rec = round(tp / max(tp + fn, 1), 4)
    f1 = round(2 * prec * rec / max(prec + rec, 1e-9), 4)
    acc = round((tp + tn) / max(len(gt_rows), 1), 4)

    summary = {
        "benchmark_scope": "100_case_extended_benchmark (75 Core + 25 PB-PERSIST-001 Auxiliary DFIR Track)",
        "total_cases_evaluated": len(gt_rows),
        "confusion_matrix": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
        "metrics": {
            "precision": prec,
            "recall": rec,
            "f1_score": f1,
            "accuracy": acc,
            "mean_fitness_conformant": round(sum(fit_conf) / max(len(fit_conf), 1), 4),
            "mean_fitness_deviating": round(sum(fit_dev) / max(len(fit_dev), 1), 4),
        },
        "per_stratum_confusion_matrix": stratum_stats,
        "evaluated_at": utc_now_iso(),
    }

    eval_path = ROOT_DIR / "research" / "evaluation" / "empirical_100_case_results.json"
    eval_path.parent.mkdir(parents=True, exist_ok=True)
    eval_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def run_noisy_log_stress_test(
    noise_levels: List[float] = None,
    seed: int = 42,
) -> Dict[str, Any]:
    """
    Noisy SOC Log Stress-Test Mode:
    Injects deterministic rates of (a) unmapped free-text analyst activity labels and
    (b) timestamp jitter (causing apparent out-of-order logging across adjacent steps)
    into the benchmark traces without modifying ground_truth_labels, producing realistic
    Precision, Recall, F1, False Positive Rate, and Mean Fitness sensitivity curves.
    """
    import random

    if noise_levels is None:
        noise_levels = [0.0, 0.10, 0.20, 0.35, 0.50]

    with db_manager.connection() as conn:
        cnt = conn.execute("SELECT COUNT(*) FROM cases WHERE case_id LIKE 'CASE-BM-%'").fetchone()[0]
    if cnt < 100:
        populate_100_case_benchmark()

    with db_manager.connection() as conn:
        gt_rows = conn.execute(
            "SELECT * FROM ground_truth_labels WHERE case_id LIKE 'CASE-BM-%' ORDER BY case_id ASC"
        ).fetchall()
        orig_acts = conn.execute(
            "SELECT * FROM analyst_activities WHERE case_id LIKE 'CASE-BM-%' ORDER BY case_id ASC, normalized_utc_timestamp ASC"
        ).fetchall()

    acts_backup = [dict(r) for r in orig_acts]
    unmapped_noise_labels = [
        "Checked internal ticket queue",
        "Consulted Tier 2 Slack channel",
        "Reviewed firewall dashboard",
        "Verified asset owner in CMDB",
    ]

    curve_points = []
    try:
        for nl in noise_levels:
            rng = random.Random(seed + int(nl * 1000))
            with db_manager.connection() as conn:
                for act in acts_backup:
                    new_step_id = act["playbook_step_id"]
                    new_act_name = act["activity"]
                    new_ts = act["normalized_utc_timestamp"]

                    # Inject unmapped free-text label noise
                    if nl > 0 and rng.random() < nl:
                        new_step_id = None
                        new_act_name = rng.choice(unmapped_noise_labels)

                    # Inject timestamp jitter (+/- 8 minutes) to simulate coarse logging granularity
                    if nl > 0 and rng.random() < (nl * 0.6) and new_ts:
                        # Swap minute digits deterministically to create occasional timestamp inversion
                        mm = int(new_ts[14:16])
                        shifted_mm = max(1, min(58, mm + rng.choice([-8, 8])))
                        new_ts = f"{new_ts[:14]}{shifted_mm:02d}{new_ts[16:]}"

                    conn.execute(
                        """
                        UPDATE analyst_activities
                        SET playbook_step_id = ?, activity = ?, normalized_utc_timestamp = ?
                        WHERE activity_record_id = ?
                        """,
                        (new_step_id, new_act_name, new_ts, act["activity_record_id"]),
                    )

            tp = tn = fp = fn = 0
            fit_conf, fit_dev = [], []
            for gt in gt_rows:
                cid = gt["case_id"]
                expected_dev = gt["conformance_class"] == "deviating"
                conf = pm4py_service.check_conformance_alignments(cid)
                predicted_dev = not conf["is_conformant"]
                if expected_dev and predicted_dev:
                    tp += 1
                elif not expected_dev and not predicted_dev:
                    tn += 1
                elif not expected_dev and predicted_dev:
                    fp += 1
                else:
                    fn += 1
                (fit_dev if expected_dev else fit_conf).append(conf["fitness"])

            prec = round(tp / max(tp + fp, 1), 4)
            rec = round(tp / max(tp + fn, 1), 4)
            f1 = round(2 * prec * rec / max(prec + rec, 1e-9), 4)
            fpr = round(fp / max(fp + tn, 1), 4)
            curve_points.append({
                "noise_rate": nl,
                "confusion_matrix": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
                "precision": prec,
                "recall": rec,
                "f1_score": f1,
                "false_positive_rate": fpr,
                "mean_fitness_conformant": round(sum(fit_conf) / max(len(fit_conf), 1), 4),
                "mean_fitness_deviating": round(sum(fit_dev) / max(len(fit_dev), 1), 4),
            })
    finally:
        # Always restore clean benchmark analyst_activities after stress-test sweep
        with db_manager.connection() as conn:
            for act in acts_backup:
                conn.execute(
                    """
                    UPDATE analyst_activities
                    SET playbook_step_id = ?, activity = ?, normalized_utc_timestamp = ?
                    WHERE activity_record_id = ?
                    """,
                    (act["playbook_step_id"], act["activity"], act["normalized_utc_timestamp"], act["activity_record_id"]),
                )

    report = {
        "stress_test_name": "Noisy SOC Log Sensitivity Evaluation (Unmapped Free-Text + Timestamp Jitter)",
        "cases_per_sweep": len(gt_rows),
        "seed": seed,
        "sensitivity_curve": curve_points,
        "executed_at": utc_now_iso(),
    }
    stress_path = ROOT_DIR / "research" / "evaluation" / "noisy_log_stress_test_results.json"
    stress_path.parent.mkdir(parents=True, exist_ok=True)
    stress_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
