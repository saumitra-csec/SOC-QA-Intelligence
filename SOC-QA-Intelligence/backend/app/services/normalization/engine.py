import json
import re
import uuid
from datetime import datetime, timezone
from dateutil import parser as date_parser
from typing import Any, Dict, List, Optional, Tuple

from backend.app.core.config import settings
from backend.app.core.database import db_manager, utc_now_iso

CANONICAL_SCHEMA_FIELDS = {
    "analyst_activity": [
        "case_id",
        "activity",
        "timestamp",
        "incident_type",
        "analyst_id",
        "analyst_role",
        "playbook_id",
        "playbook_version",
        "playbook_step_id",
        "activity_status",
        "outcome",
        "source_system",
        "evidence_reference",
    ],
    "security_telemetry": [
        "event_id",
        "timestamp",
        "host",
        "source_ip",
        "destination_ip",
        "username",
        "event_type",
        "process_image",
        "parent_image",
        "command_line",
        "script_block_id",
        "script_block_text",
        "file_path",
        "file_hash",
        "source_corpus",
    ],
    "phishing": [
        "message_id",
        "timestamp",
        "sender",
        "recipient",
        "reply_to",
        "subject",
        "body",
        "URLs",
        "attachment_names",
        "attachment_hashes",
        "classification",
        "source_corpus",
    ],
    "password_spray": [
        "timestamp",
        "event_id",
        "source_ip",
        "target_account",
        "host",
        "logon_type",
        "authentication_result",
        "failure_reason",
        "application",
        "tenant",
        "user_agent",
    ],
    "powershell": [
        "timestamp",
        "host",
        "user",
        "event_id",
        "process_image",
        "parent_image",
        "command_line",
        "process_id",
        "script_block_id",
        "script_block_text",
        "file_path",
        "file_hash",
        "destination_ip",
        "destination_domain",
        "destination_port",
    ],
}

AMBIGUOUS_DATE_RE = re.compile(r"^(\d{1,2})/(\d{1,2})/(\d{2,4})(?:\s+.*)?$")


def normalize_timestamp_value(raw_ts: Any) -> Dict[str, Optional[str]]:
    """
    Normalizes timestamps to UTC ISO 8601 while preserving:
    - original_timestamp
    - original_timezone (when available)
    - normalized_utc_timestamp
    - parsing_status
    Flags ambiguous day/month timestamps (e.g., 04/05/2026 where both <= 12) for manual review.
    Never fabricates timestamps when missing.
    """
    if raw_ts is None or str(raw_ts).strip() == "":
        return {
            "original_timestamp": None,
            "original_timezone": None,
            "normalized_utc_timestamp": None,
            "parsing_status": "MISSING_TIMESTAMP",
            "is_ambiguous": False,
        }
    raw_str = str(raw_ts).strip()
    ambig_match = AMBIGUOUS_DATE_RE.match(raw_str)
    is_ambig_date = False
    if ambig_match:
        p1, p2 = int(ambig_match.group(1)), int(ambig_match.group(2))
        if 1 <= p1 <= 12 and 1 <= p2 <= 12 and p1 != p2:
            is_ambig_date = True

    try:
        dt = date_parser.parse(raw_str)
    except Exception:
        return {
            "original_timestamp": raw_str,
            "original_timezone": None,
            "normalized_utc_timestamp": None,
            "parsing_status": "INVALID_TIMESTAMP",
            "is_ambiguous": False,
        }

    if dt.tzinfo is not None:
        orig_tz = dt.tzname() or str(dt.tzinfo)
        utc_dt = dt.astimezone(timezone.utc)
        status = "AMBIGUOUS_TIMEZONE_FLAGGED" if is_ambig_date else (
            "VALID_UTC" if orig_tz in ("UTC", "Z", "+00:00") else "CONVERTED_TO_UTC"
        )
    else:
        orig_tz = None
        utc_dt = dt.replace(tzinfo=timezone.utc)
        status = "AMBIGUOUS_TIMEZONE_FLAGGED"

    return {
        "original_timestamp": raw_str,
        "original_timezone": orig_tz,
        "normalized_utc_timestamp": utc_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "parsing_status": status,
        "is_ambiguous": status == "AMBIGUOUS_TIMEZONE_FLAGGED",
    }


def save_schema_mapping(
    mapping_name: str,
    target_schema_type: str,
    field_mapping: Dict[str, str],
    created_by: str = "researcher",
) -> Dict[str, Any]:
    if target_schema_type not in CANONICAL_SCHEMA_FIELDS:
        raise ValueError(f"Unsupported target_schema_type '{target_schema_type}'")
    mapping_id = f"MAP-{uuid.uuid4().hex[:8].upper()}"
    now_iso = utc_now_iso()
    with db_manager.connection() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO schema_mappings (
                mapping_id, mapping_name, target_schema_type, mapping_json, created_by, created_at
            ) VALUES (
                COALESCE((SELECT mapping_id FROM schema_mappings WHERE mapping_name = ?), ?),
                ?, ?, ?, ?, ?
            )
            """,
            (
                mapping_name,
                mapping_id,
                mapping_name,
                target_schema_type,
                json.dumps(field_mapping),
                created_by,
                now_iso,
            ),
        )
        row = conn.execute(
            "SELECT * FROM schema_mappings WHERE mapping_name = ?", (mapping_name,)
        ).fetchone()
    return dict(row)


def classify_analyst_timeline_category(activity_name: str) -> str:
    low = (activity_name or "").lower()
    if any(k in low for k in ("escalat", "tier 2", "tier2", "incident commander")):
        return "escalation_event"
    if any(k in low for k in ("evidence", "hash", "attach", "artifact", "collect")):
        return "evidence_addition"
    if any(k in low for k in ("status", "close", "open", "triage start", "contain")):
        return "case_status_transition"
    return "analyst_activity"


def normalize_dataset(
    dataset_id: str,
    target_schema_type: str,
    field_mapping: Dict[str, str],
    normalization_version: str = "norm-v1.0",
) -> Dict[str, Any]:
    """
    Executes the dedicated normalization pipeline on a dataset's raw records.
    - Never modifies the original raw file or raw_records table.
    - Populates only fields supported by source data (never fabricates values).
    - Retains original source field names alongside normalized fields.
    - Writes a separate normalized JSON file in data/normalized/.
    """
    if target_schema_type not in CANONICAL_SCHEMA_FIELDS:
        raise ValueError(f"Unsupported target_schema_type '{target_schema_type}'")

    allowed_fields = set(CANONICAL_SCHEMA_FIELDS[target_schema_type])
    unsupported_targets = [
        tgt for tgt in field_mapping.values() if tgt not in allowed_fields and tgt != "case_id"
    ]

    with db_manager.connection() as conn:
        ds = conn.execute(
            "SELECT * FROM datasets WHERE dataset_id = ?", (dataset_id,)
        ).fetchone()
        if not ds:
            raise ValueError(f"Dataset '{dataset_id}' not found.")
        raw_rows = conn.execute(
            "SELECT * FROM raw_records WHERE dataset_id = ? AND is_malformed = 0 ORDER BY row_index ASC",
            (dataset_id,),
        ).fetchall()

        # Clear prior normalization records for this dataset so re-runs are idempotent
        conn.execute("DELETE FROM normalized_events WHERE dataset_id = ?", (dataset_id,))
        conn.execute("DELETE FROM analyst_activities WHERE dataset_id = ?", (dataset_id,))

        now_iso = utc_now_iso()
        normalized_output_records = []
        valid_ts_count = 0
        ambiguous_ts_count = 0
        invalid_ts_count = 0

        for r in raw_rows:
            orig_dict = json.loads(r["raw_payload_json"])
            norm_dict: Dict[str, Any] = {}

            # Only populate fields present in source data via explicit mapping or exact canonical match
            for src_key, src_val in orig_dict.items():
                if src_key.startswith("_") or src_val in ("", None):
                    continue
                target_key = field_mapping.get(src_key)
                if not target_key and (src_key in allowed_fields or src_key == 'case_id'):
                    target_key = src_key
                if target_key and (target_key in allowed_fields or target_key == "case_id"):
                    norm_dict[target_key] = src_val

            ts_meta = normalize_timestamp_value(norm_dict.get("timestamp"))
            if ts_meta["parsing_status"] in ("VALID_UTC", "CONVERTED_TO_UTC"):
                valid_ts_count += 1
            elif ts_meta["parsing_status"] == "AMBIGUOUS_TIMEZONE_FLAGGED":
                ambiguous_ts_count += 1
            else:
                invalid_ts_count += 1

            norm_dict["timestamp"] = ts_meta["normalized_utc_timestamp"]

            if target_schema_type == "analyst_activity":
                act_id = f"ACT-{uuid.uuid4().hex[:10].upper()}"
                case_val = norm_dict.get("case_id") or "UNASSOCIATED"
                act_name = norm_dict.get("activity") or "UNMAPPED_ACTIVITY"
                t_cat = classify_analyst_timeline_category(act_name)
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
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        act_id,
                        dataset_id,
                        r["raw_record_id"],
                        case_val,
                        act_name,
                        ts_meta["original_timestamp"],
                        ts_meta["original_timezone"],
                        ts_meta["normalized_utc_timestamp"],
                        ts_meta["parsing_status"],
                        norm_dict.get("incident_type"),
                        norm_dict.get("analyst_id"),
                        norm_dict.get("analyst_role"),
                        norm_dict.get("playbook_id"),
                        norm_dict.get("playbook_version"),
                        norm_dict.get("playbook_step_id"),
                        norm_dict.get("activity_status"),
                        norm_dict.get("outcome"),
                        norm_dict.get("source_system"),
                        norm_dict.get("evidence_reference"),
                        t_cat,
                        json.dumps(orig_dict),
                        now_iso,
                    ),
                )
                record_id = act_id
            else:
                ev_id = f"NEV-{uuid.uuid4().hex[:10].upper()}"
                conn.execute(
                    """
                    INSERT INTO normalized_events (
                        event_record_id, dataset_id, raw_record_id, schema_type,
                        case_id, event_id, original_timestamp, original_timezone,
                        normalized_utc_timestamp, timestamp_parsing_status,
                        host, source_ip, destination_ip, username, event_type,
                        EventCategory, normalized_fields_json, original_fields_json,
                        normalization_version, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ev_id,
                        dataset_id,
                        r["raw_record_id"],
                        target_schema_type,
                        norm_dict.get("case_id"),
                        norm_dict.get("event_id") or norm_dict.get("message_id"),
                        ts_meta["original_timestamp"],
                        ts_meta["original_timezone"],
                        ts_meta["normalized_utc_timestamp"],
                        ts_meta["parsing_status"],
                        norm_dict.get("host"),
                        norm_dict.get("source_ip") or norm_dict.get("sender"),
                        norm_dict.get("destination_ip") or norm_dict.get("recipient"),
                        norm_dict.get("username") or norm_dict.get("target_account") or norm_dict.get("user"),
                        norm_dict.get("event_type") or norm_dict.get("classification") or norm_dict.get("authentication_result"),
                        "security_telemetry",
                        json.dumps(norm_dict),
                        json.dumps(orig_dict),
                        normalization_version,
                        now_iso,
                    ),
                )
                record_id = ev_id

            normalized_output_records.append(
                {
                    "record_id": record_id,
                    "raw_record_id": r["raw_record_id"],
                    "schema_type": target_schema_type,
                    "timestamp_metadata": ts_meta,
                    "normalized_fields": norm_dict,
                    "original_fields": orig_dict,
                }
            )

        conn.execute(
            "UPDATE datasets SET processing_status = 'normalized', normalization_version = ? WHERE dataset_id = ?",
            (normalization_version, dataset_id),
        )
        conn.execute(
            "UPDATE source_manifest SET processing_status = 'normalized', normalization_version = ? WHERE dataset_id = ?",
            (normalization_version, dataset_id),
        )
        conn.execute(
            """
            INSERT INTO processing_runs (run_id, dataset_id, pipeline_stage, mapping_id, parameters_json, status, executed_at)
            VALUES (?, ?, 'normalization', NULL, ?, 'completed', ?)
            """,
            (
                f"RUN-{uuid.uuid4().hex[:8].upper()}",
                dataset_id,
                json.dumps(
                    {
                        "target_schema_type": target_schema_type,
                        "field_mapping": field_mapping,
                        "unsupported_targets": unsupported_targets,
                    }
                ),
                now_iso,
            ),
        )

    # Persist separate normalized dataset artifact on disk without touching raw file
    norm_file_path = settings.normalized_storage_dir / f"{dataset_id}_normalized.json"
    norm_file_path.write_text(
        json.dumps(
            {
                "dataset_id": dataset_id,
                "normalization_version": normalization_version,
                "target_schema_type": target_schema_type,
                "generated_at": now_iso,
                "records": normalized_output_records,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    return {
        "dataset_id": dataset_id,
        "target_schema_type": target_schema_type,
        "normalization_version": normalization_version,
        "normalized_count": len(normalized_output_records),
        "timestamp_summary": {
            "valid_utc_or_converted": valid_ts_count,
            "ambiguous_flagged_for_review": ambiguous_ts_count,
            "invalid_or_missing": invalid_ts_count,
        },
        "unsupported_mapping_targets": unsupported_targets,
        "normalized_file_path": str(norm_file_path),
        "sample_normalized_records": normalized_output_records[:5],
    }
