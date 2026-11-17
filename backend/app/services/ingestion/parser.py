import csv
import hashlib
import io
import json
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Tuple
import chardet

from backend.app.core.config import settings
from backend.app.core.database import db_manager, utc_now_iso
from backend.app.core.security import (
    compute_sha256_bytes,
    validate_upload_constraints,
)

VALID_DATASET_CATEGORIES = {
    "phishing_telemetry",
    "password_spray_telemetry",
    "suspicious_powershell_telemetry",
    "analyst_activity_logs",
    "case_metadata",
    "reference_playbooks",
    "evidence_metadata",
    "ground_truth_annotations",
}

CATEGORY_EXPECTED_FIELDS = {
    "phishing_telemetry": ["sender", "recipient", "subject", "body", "timestamp"],
    "password_spray_telemetry": [
        "timestamp",
        "source_ip",
        "target_account",
        "authentication_result",
    ],
    "suspicious_powershell_telemetry": [
        "timestamp",
        "host",
        "command_line",
        "script_block_text",
    ],
    "analyst_activity_logs": ["case_id", "activity", "timestamp", "analyst_id"],
    "case_metadata": ["case_id", "incident_category", "case_status"],
    "reference_playbooks": ["playbook_id", "version", "incident_type", "step_id"],
    "evidence_metadata": ["evidence_id", "case_id", "evidence_type"],
    "ground_truth_annotations": ["case_id", "conformance_class", "deviation_type"],
}

TIMESTAMP_CANDIDATE_TOKENS = (
    "timestamp",
    "time",
    "date",
    "eventtime",
    "utc",
    "created_at",
    "time:timestamp",
)
CASE_ID_CANDIDATE_TOKENS = (
    "case_id",
    "caseid",
    "investigation_id",
    "incident_id",
    "concept:name",
    "trace_id",
)

DEFAULT_FIELD_SYNONYMS = {
    "eventtime": "timestamp",
    "time:timestamp": "timestamp",
    "date": "timestamp",
    "datetime": "timestamp",
    "targetusername": "target_account",
    "user": "username",
    "accountname": "username",
    "activityname": "activity",
    "concept:name": "activity",
    "trace:concept:name": "case_id",
    "caseid": "case_id",
    "incidentid": "case_id",
    "src_ip": "source_ip",
    "ipaddress": "source_ip",
    "dest_ip": "destination_ip",
    "commandline": "command_line",
    "scriptblocktext": "script_block_text",
    "scriptblockid": "script_block_id",
    "parentimage": "parent_image",
    "image": "process_image",
    "newprocessname": "process_image",
    "parentprocessname": "parent_image",
    "processcommandline": "command_line",
    "computer": "host",
    "ipaddress": "source_ip",
    "subjectusername": "username",
    "logontype": "logon_type",
    "status": "authentication_result",
    "substatus": "failure_reason",
    "receiver": "recipient",
    "org:resource": "analyst_id",
    "org:role": "analyst_role",
}


def detect_encoding(content: bytes) -> str:
    detected = chardet.detect(content[:32768])
    enc = (detected.get("encoding") or "utf-8").lower()
    if enc in ("ascii", "utf-8-sig"):
        return "utf-8"
    return enc


def parse_csv_bytes(text: str) -> Tuple[List[Dict[str, Any]], List[int]]:
    records: List[Dict[str, Any]] = []
    malformed_rows: List[int] = []
    reader = csv.reader(io.StringIO(text))
    try:
        headers = next(reader)
    except StopIteration:
        raise ValueError("CSV file contains no header row.")
    headers = [h.strip() for h in headers]
    if not any(headers):
        raise ValueError("CSV header row contains no valid column names.")
    expected_len = len(headers)
    for idx, row in enumerate(reader, start=1):
        if not any(cell.strip() for cell in row):
            continue
        if len(row) != expected_len:
            malformed_rows.append(idx)
            padded = (row + [""] * expected_len)[:expected_len]
            rec = dict(zip(headers, padded))
            rec["_malformed_reason"] = f"Column count mismatch: got {len(row)}, expected {expected_len}"
            records.append(rec)
        else:
            records.append(dict(zip(headers, [c.strip() for c in row])))
    return records, malformed_rows


def parse_json_bytes(text: str) -> Tuple[List[Dict[str, Any]], List[int]]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Malformed JSON file: {exc}") from exc
    if isinstance(data, dict):
        if "records" in data and isinstance(data["records"], list):
            items = data["records"]
        elif "events" in data and isinstance(data["events"], list):
            items = data["events"]
        elif "steps" in data and isinstance(data["steps"], list):
            items = [data]
        else:
            items = [data]
    elif isinstance(data, list):
        items = data
    else:
        raise ValueError("JSON root must be an array of objects or a structured object.")

    records: List[Dict[str, Any]] = []
    malformed: List[int] = []
    for idx, item in enumerate(items, start=1):
        if isinstance(item, dict):
            # Flatten nested Windows Event Log 'event_data' objects while preserving original keys
            if isinstance(item.get("event_data"), dict):
                flat = {k: v for k, v in item.items() if k != "event_data"}
                for ed_k, ed_v in item["event_data"].items():
                    if ed_k not in flat:
                        flat[ed_k] = ed_v
                records.append(flat)
            else:
                records.append(item)
        else:
            malformed.append(idx)
            records.append({"_raw_value": str(item), "_malformed_reason": "Record is not a JSON object"})
    return records, malformed


def parse_jsonl_bytes(text: str) -> Tuple[List[Dict[str, Any]], List[int]]:
    records: List[Dict[str, Any]] = []
    malformed: List[int] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
            if isinstance(obj, dict):
                records.append(obj)
            else:
                malformed.append(idx)
                records.append({"_raw_line": stripped, "_malformed_reason": "JSONL line is not a JSON object"})
        except json.JSONDecodeError as exc:
            malformed.append(idx)
            records.append({"_raw_line": stripped, "_malformed_reason": f"Invalid JSONL syntax: {exc}"})
    if not records:
        raise ValueError("JSONL/NDJSON file contains no records.")
    return records, malformed


def parse_xes_bytes(text: str) -> Tuple[List[Dict[str, Any]], List[int]]:
    """Parses IEEE 1849-2016 XES XML event logs into flat event dictionaries."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError(f"Malformed XES XML structure: {exc}") from exc

    def strip_ns(tag: str) -> str:
        return tag.split("}", 1)[-1] if "}" in tag else tag

    if strip_ns(root.tag) != "log":
        raise ValueError(f"Invalid XES root element '{root.tag}'; expected '<log>'.")

    records: List[Dict[str, Any]] = []
    malformed: List[int] = []
    row_idx = 0
    for trace in root:
        if strip_ns(trace.tag) != "trace":
            continue
        trace_attrs: Dict[str, Any] = {}
        for child in trace:
            ctag = strip_ns(child.tag)
            if ctag in ("string", "date", "int", "float", "boolean"):
                key = child.attrib.get("key", "")
                val = child.attrib.get("value", "")
                if key == "concept:name":
                    trace_attrs["case_id"] = val
                    trace_attrs["trace:concept:name"] = val
                else:
                    trace_attrs[f"trace:{key}"] = val
            elif ctag == "event":
                row_idx += 1
                ev_dict = dict(trace_attrs)
                for ev_attr in child:
                    etag = strip_ns(ev_attr.tag)
                    if etag in ("string", "date", "int", "float", "boolean"):
                        k = ev_attr.attrib.get("key", "")
                        v = ev_attr.attrib.get("value", "")
                        ev_dict[k] = v
                if "concept:name" in ev_dict and "activity" not in ev_dict:
                    ev_dict["activity"] = ev_dict["concept:name"]
                if "time:timestamp" in ev_dict and "timestamp" not in ev_dict:
                    ev_dict["timestamp"] = ev_dict["time:timestamp"]
                if "org:resource" in ev_dict and "analyst_id" not in ev_dict:
                    ev_dict["analyst_id"] = ev_dict["org:resource"]
                if not ev_dict.get("case_id") or not ev_dict.get("activity"):
                    malformed.append(row_idx)
                    ev_dict["_malformed_reason"] = "XES event missing trace concept:name (case_id) or event concept:name (activity)"
                records.append(ev_dict)
    if not records:
        raise ValueError("XES log contains no <event> elements.")
    return records, malformed


def infer_schema_details(records: List[Dict[str, Any]], category: str) -> Dict[str, Any]:
    all_fields = []
    seen = set()
    for r in records[:100]:
        for k in r.keys():
            if not k.startswith("_") and k not in seen:
                seen.add(k)
                all_fields.append(k)

    ts_cols = [
        f for f in all_fields if any(tok in f.lower() for tok in TIMESTAMP_CANDIDATE_TOKENS)
    ]
    case_cols = [
        f for f in all_fields if any(tok in f.lower() for tok in CASE_ID_CANDIDATE_TOKENS)
    ]
    inferred_mapping = {}
    for f in all_fields:
        low = f.lower().replace(" ", "_")
        if low in DEFAULT_FIELD_SYNONYMS:
            inferred_mapping[f] = DEFAULT_FIELD_SYNONYMS[low]
        else:
            inferred_mapping[f] = low

    expected = CATEGORY_EXPECTED_FIELDS.get(category, [])
    mapped_targets = set(inferred_mapping.values())
    missing_expected = [ef for ef in expected if ef not in mapped_targets]

    return {
        "detected_fields": all_fields,
        "potential_timestamp_columns": ts_cols,
        "potential_case_id_columns": case_cols,
        "inferred_schema_mapping": inferred_mapping,
        "missing_expected_fields": missing_expected,
    }


def ingest_dataset_file(
    filename: str,
    content: bytes,
    category: str,
    dataset_name: str = None,
    source_url: str = "",
    source_organization: str = "Local Researcher Upload",
    dataset_version: str = "1.0",
    acquisition_date: str = None,
    license_info: str = "Academic Research / CC-BY-4.0",
) -> Dict[str, Any]:
    """
    Ingests an uploaded dataset file, preserves the original raw file unchanged on disk,
    calculates its SHA-256 checksum, inspects records without silently discarding any,
    and writes provenance and ingestion job summaries to the relational database.
    """
    if category not in VALID_DATASET_CATEGORIES:
        raise ValueError(
            f"Invalid dataset category '{category}'. Must be one of {sorted(VALID_DATASET_CATEGORIES)}"
        )

    safe_name, file_format = validate_upload_constraints(filename, content)
    encoding = detect_encoding(content)
    text = content.decode(encoding, errors="replace")

    if file_format == "csv":
        records, malformed_rows = parse_csv_bytes(text)
    elif file_format == "json":
        records, malformed_rows = parse_json_bytes(text)
    elif file_format in ("jsonl", "ndjson"):
        records, malformed_rows = parse_jsonl_bytes(text)
    elif file_format == "xes":
        records, malformed_rows = parse_xes_bytes(text)
    else:
        raise ValueError(f"Unsupported format: {file_format}")

    dataset_id = f"DS-{uuid.uuid4().hex[:8].upper()}"
    file_id = f"FILE-{uuid.uuid4().hex[:8].upper()}"
    job_id = f"JOB-{uuid.uuid4().hex[:8].upper()}"
    manifest_id = f"MAN-{uuid.uuid4().hex[:8].upper()}"
    now_iso = utc_now_iso()
    acq_date = acquisition_date or now_iso[:10]
    sha256_digest = compute_sha256_bytes(content)

    # Preserve raw file unchanged on disk
    stored_raw_path = settings.raw_storage_dir / f"{dataset_id}_{safe_name}"
    stored_raw_path.write_bytes(content)

    schema_info = infer_schema_details(records, category)
    malformed_set = set(malformed_rows)

    seen_hashes = set()
    accepted_count = 0
    rejected_count = 0
    duplicate_count = 0
    warning_count = 0
    associated_cases = set()

    raw_rows_to_insert = []
    for idx, rec in enumerate(records, start=1):
        canonical_payload = json.dumps(rec, sort_keys=True)
        rec_hash = hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()
        is_dup = 1 if rec_hash in seen_hashes else 0
        seen_hashes.add(rec_hash)
        is_mal = 1 if idx in malformed_set else 0

        warnings = []
        if is_dup:
            duplicate_count += 1
            warnings.append("Exact duplicate record hash detected in dataset")
        if is_mal:
            rejected_count += 1
            warnings.append(rec.get("_malformed_reason", "Malformed record structure"))
        else:
            accepted_count += 1

        # Check for empty values in key columns
        empty_keys = [k for k, v in rec.items() if v in ("", None) and not k.startswith("_")]
        if empty_keys:
            warnings.append(f"Empty fields: {', '.join(empty_keys[:4])}")
        if warnings and not is_mal:
            warning_count += 1

        # Track candidate case IDs
        for ccol in schema_info["potential_case_id_columns"]:
            val = rec.get(ccol)
            if val and isinstance(val, str) and val.strip():
                associated_cases.add(val.strip())

        raw_rows_to_insert.append(
            (
                f"RAW-{dataset_id}-{idx:05d}",
                dataset_id,
                idx,
                canonical_payload,
                rec_hash,
                is_mal,
                is_dup,
                json.dumps(warnings),
                now_iso,
            )
        )

    with db_manager.connection() as conn:
        conn.execute(
            """
            INSERT INTO datasets (
                dataset_id, name, category, source_url, source_organization,
                dataset_version, acquisition_date, upload_date, license_info,
                processing_status, normalization_version, record_count,
                accepted_count, rejected_count, duplicate_count, warning_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                dataset_id,
                dataset_name or safe_name,
                category,
                source_url,
                source_organization,
                dataset_version,
                acq_date,
                now_iso,
                license_info,
                "inspected",
                "norm-v1.0",
                len(records),
                accepted_count,
                rejected_count,
                duplicate_count,
                warning_count,
            ),
        )
        conn.execute(
            """
            INSERT INTO dataset_files (
                file_id, dataset_id, original_filename, stored_raw_path,
                file_format, file_size_bytes, encoding, sha256_checksum, uploaded_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                file_id,
                dataset_id,
                safe_name,
                str(stored_raw_path),
                file_format,
                len(content),
                encoding,
                sha256_digest,
                now_iso,
            ),
        )
        conn.execute(
            """
            INSERT INTO source_manifest (
                manifest_id, dataset_id, original_filename, original_source_url,
                source_organization, dataset_version, acquisition_date, upload_date,
                file_format, file_size_bytes, license_information, sha256_checksum,
                processing_status, normalization_version, associated_case_ids_json,
                last_verified_at, integrity_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                manifest_id,
                dataset_id,
                safe_name,
                source_url,
                source_organization,
                dataset_version,
                acq_date,
                now_iso,
                file_format,
                len(content),
                license_info,
                sha256_digest,
                "inspected",
                "norm-v1.0",
                json.dumps(sorted(associated_cases)),
                now_iso,
                "VERIFIED",
            ),
        )
        conn.executemany(
            """
            INSERT INTO raw_records (
                raw_record_id, dataset_id, row_index, raw_payload_json,
                record_hash, is_malformed, is_duplicate, parse_warnings_json, ingested_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            raw_rows_to_insert,
        )
        conn.execute(
            """
            INSERT INTO ingestion_jobs (
                job_id, dataset_id, file_id, status, total_records,
                accepted_records, rejected_records, duplicate_records, warning_records,
                inferred_timestamp_cols_json, inferred_case_id_cols_json,
                detected_fields_json, missing_fields_json, error_summary,
                started_at, completed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                job_id,
                dataset_id,
                file_id,
                "completed",
                len(records),
                accepted_count,
                rejected_count,
                duplicate_count,
                warning_count,
                json.dumps(schema_info["potential_timestamp_columns"]),
                json.dumps(schema_info["potential_case_id_columns"]),
                json.dumps(schema_info["detected_fields"]),
                json.dumps(schema_info["missing_expected_fields"]),
                None,
                now_iso,
                now_iso,
            ),
        )

    db_manager.log_audit(
        actor="researcher",
        action_type="DATASET_INGESTED",
        entity_type="dataset",
        entity_id=dataset_id,
        details={
            "filename": safe_name,
            "category": category,
            "sha256": sha256_digest,
            "total_records": len(records),
            "accepted": accepted_count,
            "rejected": rejected_count,
            "duplicates": duplicate_count,
        },
    )

    return {
        "dataset_id": dataset_id,
        "file_id": file_id,
        "job_id": job_id,
        "manifest_id": manifest_id,
        "original_filename": safe_name,
        "category": category,
        "file_format": file_format,
        "file_size_bytes": len(content),
        "encoding": encoding,
        "sha256_checksum": sha256_digest,
        "summary": {
            "total_records": len(records),
            "accepted_count": accepted_count,
            "rejected_count": rejected_count,
            "duplicate_count": duplicate_count,
            "warning_count": warning_count,
        },
        "inspection": schema_info,
        "associated_case_ids": sorted(associated_cases),
        "preview_records": records[:10],
    }
