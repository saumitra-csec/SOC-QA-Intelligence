import json
import re
import uuid
from typing import Any, Dict, List

from backend.app.core.database import db_manager, utc_now_iso

CASE_ID_FORMAT_RE = re.compile(r"^CASE-[A-Z0-9_-]{3,20}$")


def evaluate_dataset_quality(dataset_id: str) -> Dict[str, Any]:
    """
    Assesses 9 data quality & research readiness dimensions for a dataset:
    1. Missing mandatory fields
    2. Invalid timestamps
    3. Duplicate records
    4. Unmapped activities
    5. Unassociated records
    6. Missing evidence references
    7. Inconsistent incident classifications
    8. Invalid case identifiers
    9. Unsupported schema mappings

    Strictly distinguishes Data Quality from Investigation Quality.
    """
    with db_manager.connection() as conn:
        ds = conn.execute(
            "SELECT * FROM datasets WHERE dataset_id = ?", (dataset_id,)
        ).fetchone()
        if not ds:
            raise ValueError(f"Dataset '{dataset_id}' not found.")

        raw_rows = conn.execute(
            "SELECT * FROM raw_records WHERE dataset_id = ?", (dataset_id,)
        ).fetchall()
        norm_events = conn.execute(
            "SELECT * FROM normalized_events WHERE dataset_id = ?", (dataset_id,)
        ).fetchall()
        analyst_acts = conn.execute(
            "SELECT * FROM analyst_activities WHERE dataset_id = ?", (dataset_id,)
        ).fetchall()
        runs = conn.execute(
            "SELECT * FROM processing_runs WHERE dataset_id = ? AND pipeline_stage = 'normalization' ORDER BY executed_at DESC LIMIT 1",
            (dataset_id,),
        ).fetchall()

        duplicate_records_count = sum(1 for r in raw_rows if r["is_duplicate"] == 1)
        malformed_count = sum(1 for r in raw_rows if r["is_malformed"] == 1)

        unsupported_mappings_count = 0
        if runs:
            params = json.loads(runs[0]["parameters_json"])
            unsupported_mappings_count = len(params.get("unsupported_targets", []))

        missing_mandatory_fields_count = 0
        invalid_timestamps_count = 0
        unmapped_activities_count = 0
        unassociated_records_count = 0
        missing_evidence_refs_count = 0
        inconsistent_classifications_count = 0
        invalid_case_ids_count = 0

        # Evaluate analyst activity records
        for act in analyst_acts:
            if not act["case_id"] or act["case_id"] == "UNASSOCIATED":
                unassociated_records_count += 1
                missing_mandatory_fields_count += 1
            elif not CASE_ID_FORMAT_RE.match(act["case_id"]):
                invalid_case_ids_count += 1

            if not act["activity"] or act["activity"] == "UNMAPPED_ACTIVITY":
                unmapped_activities_count += 1
                missing_mandatory_fields_count += 1

            if act["timestamp_parsing_status"] in ("INVALID_TIMESTAMP", "MISSING_TIMESTAMP"):
                invalid_timestamps_count += 1

            if not act["evidence_reference"]:
                missing_evidence_refs_count += 1

            if act["incident_type"] and act["incident_type"] not in (
                "phishing",
                "password_spraying",
                "suspicious_powershell",
            ):
                inconsistent_classifications_count += 1

        # Evaluate security telemetry records
        for nev in norm_events:
            if not nev["case_id"]:
                unassociated_records_count += 1
            elif not CASE_ID_FORMAT_RE.match(nev["case_id"]):
                invalid_case_ids_count += 1

            if nev["timestamp_parsing_status"] in ("INVALID_TIMESTAMP", "MISSING_TIMESTAMP"):
                invalid_timestamps_count += 1

            if not nev["event_id"] and not nev["source_ip"] and not nev["host"]:
                missing_mandatory_fields_count += 1

        # Determine readiness status
        if malformed_count > 0 and (len(norm_events) + len(analyst_acts)) == 0:
            readiness_status = "Rejected"
        elif (
            invalid_timestamps_count > 0
            or unmapped_activities_count > 0
            or invalid_case_ids_count > 0
            or inconsistent_classifications_count > 0
        ):
            readiness_status = "Requires review"
        elif (
            duplicate_records_count > 0
            or unassociated_records_count > 0
            or missing_evidence_refs_count > 0
            or unsupported_mappings_count > 0
            or missing_mandatory_fields_count > 0
        ):
            readiness_status = "Valid with warnings"
        else:
            readiness_status = "Valid"

        checklist = [
            {
                "check_id": "DQ-01",
                "dimension": "Missing mandatory fields",
                "count": missing_mandatory_fields_count,
                "status": "PASS" if missing_mandatory_fields_count == 0 else "WARN",
                "note": "Checks required schema fields in normalized records without fabricating missing values.",
            },
            {
                "check_id": "DQ-02",
                "dimension": "Invalid timestamps",
                "count": invalid_timestamps_count,
                "status": "PASS" if invalid_timestamps_count == 0 else "FAIL",
                "note": "Verifies UTC ISO 8601 timestamp parsing across all records.",
            },
            {
                "check_id": "DQ-03",
                "dimension": "Duplicate records",
                "count": duplicate_records_count,
                "status": "PASS" if duplicate_records_count == 0 else "WARN",
                "note": "Identifies identical SHA-256 record hashes without silently discarding rows.",
            },
            {
                "check_id": "DQ-04",
                "dimension": "Unmapped activities",
                "count": unmapped_activities_count,
                "status": "PASS" if unmapped_activities_count == 0 else "FAIL",
                "note": "Checks whether analyst activity records map to canonical activity names.",
            },
            {
                "check_id": "DQ-05",
                "dimension": "Unassociated records",
                "count": unassociated_records_count,
                "status": "PASS" if unassociated_records_count == 0 else "WARN",
                "note": "Counts records lacking explicit case_id association.",
            },
            {
                "check_id": "DQ-06",
                "dimension": "Missing evidence references",
                "count": missing_evidence_refs_count,
                "status": "PASS" if missing_evidence_refs_count == 0 else "WARN",
                "note": "Flags analyst activity logs lacking an explicit evidence_reference pointer (observability vs. documentation check).",
            },
            {
                "check_id": "DQ-07",
                "dimension": "Inconsistent incident classifications",
                "count": inconsistent_classifications_count,
                "status": "PASS" if inconsistent_classifications_count == 0 else "FAIL",
                "note": "Validates incident_type against the three benchmark categories.",
            },
            {
                "check_id": "DQ-08",
                "dimension": "Invalid case identifiers",
                "count": invalid_case_ids_count,
                "status": "PASS" if invalid_case_ids_count == 0 else "FAIL",
                "note": "Checks case_id format conformance (CASE-XXX).",
            },
            {
                "check_id": "DQ-09",
                "dimension": "Unsupported schema mappings",
                "count": unsupported_mappings_count,
                "status": "PASS" if unsupported_mappings_count == 0 else "WARN",
                "note": "Checks for user mapping fields outside the canonical target schema.",
            },
        ]

        val_id = f"VAL-{uuid.uuid4().hex[:8].upper()}"
        now_iso = utc_now_iso()
        conn.execute("DELETE FROM validation_results WHERE dataset_id = ?", (dataset_id,))
        conn.execute(
            """
            INSERT INTO validation_results (
                validation_id, dataset_id, readiness_status,
                missing_mandatory_fields_count, invalid_timestamps_count,
                duplicate_records_count, unmapped_activities_count,
                unassociated_records_count, missing_evidence_refs_count,
                inconsistent_classifications_count, invalid_case_ids_count,
                unsupported_mappings_count, checklist_json, evaluated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                val_id,
                dataset_id,
                readiness_status,
                missing_mandatory_fields_count,
                invalid_timestamps_count,
                duplicate_records_count,
                unmapped_activities_count,
                unassociated_records_count,
                missing_evidence_refs_count,
                inconsistent_classifications_count,
                invalid_case_ids_count,
                unsupported_mappings_count,
                json.dumps(checklist),
                now_iso,
            ),
        )
        conn.execute(
            "UPDATE datasets SET processing_status = 'validated' WHERE dataset_id = ?",
            (dataset_id,),
        )

    return {
        "validation_id": val_id,
        "dataset_id": dataset_id,
        "dataset_name": ds["name"],
        "category": ds["category"],
        "readiness_status": readiness_status,
        "metrics": {
            "missing_mandatory_fields": missing_mandatory_fields_count,
            "invalid_timestamps": invalid_timestamps_count,
            "duplicate_records": duplicate_records_count,
            "unmapped_activities": unmapped_activities_count,
            "unassociated_records": unassociated_records_count,
            "missing_evidence_references": missing_evidence_refs_count,
            "inconsistent_incident_classifications": inconsistent_classifications_count,
            "invalid_case_identifiers": invalid_case_ids_count,
            "unsupported_schema_mappings": unsupported_mappings_count,
        },
        "checklist": checklist,
        "methodological_note": (
            "Data quality metrics evaluate telemetry/log completeness and schema readiness only. "
            "Missing evidence references in event logs may reflect observability or documentation gaps rather than analyst procedural failure."
        ),
        "evaluated_at": now_iso,
    }
