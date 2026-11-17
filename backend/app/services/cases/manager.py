import json
import uuid
from typing import Any, Dict, List, Optional

from backend.app.core.database import db_manager, utc_now_iso


def create_or_update_case(
    case_id: str,
    incident_category: str,
    case_status: str = "open",
    playbook_id: Optional[str] = None,
    playbook_version: Optional[str] = None,
    dataset_source_id: Optional[str] = None,
    data_quality_status: str = "Valid",
    summary: str = "",
) -> Dict[str, Any]:
    now_iso = utc_now_iso()
    with db_manager.connection() as conn:
        existing = conn.execute(
            "SELECT case_id FROM cases WHERE case_id = ?", (case_id,)
        ).fetchone()
        if existing:
            conn.execute(
                """
                UPDATE cases
                SET incident_category = ?, case_status = ?, playbook_id = COALESCE(?, playbook_id),
                    playbook_version = COALESCE(?, playbook_version),
                    dataset_source_id = COALESCE(?, dataset_source_id),
                    data_quality_status = ?, summary = COALESCE(NULLIF(?, ''), summary),
                    updated_at = ?
                WHERE case_id = ?
                """,
                (
                    incident_category,
                    case_status,
                    playbook_id,
                    playbook_version,
                    dataset_source_id,
                    data_quality_status,
                    summary,
                    now_iso,
                    case_id,
                ),
            )
        else:
            conn.execute(
                """
                INSERT INTO cases (
                    case_id, incident_category, case_status, playbook_id,
                    playbook_version, dataset_source_id, data_quality_status,
                    summary, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    case_id,
                    incident_category,
                    case_status,
                    playbook_id,
                    playbook_version,
                    dataset_source_id,
                    data_quality_status,
                    summary,
                    now_iso,
                    now_iso,
                ),
            )
    return get_case_overview(case_id)


def associate_records_by_explicit_rule(
    case_id: str,
    matching_field: str = "case_id",
    matching_value: Optional[str] = None,
    associated_by: str = "system_rule_engine",
) -> Dict[str, Any]:
    """
    Associates normalized security telemetry and analyst activity events with a case
    strictly through explicit identifier or deterministic field matching rules.
    Never associates events merely by timestamp proximity.
    """
    target_val = matching_value or case_id
    now_iso = utc_now_iso()
    linked_events = 0
    linked_activities = 0

    with db_manager.connection() as conn:
        c_row = conn.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
        if not c_row:
            raise ValueError(f"Case '{case_id}' does not exist.")

        if matching_field == "case_id":
            ev_rows = conn.execute(
                "SELECT event_record_id FROM normalized_events WHERE case_id = ?",
                (target_val,),
            ).fetchall()
        else:
            ev_rows = conn.execute(
                f"SELECT event_record_id FROM normalized_events WHERE {matching_field} = ?",
                (target_val,),
            ).fetchall()

        for er in ev_rows:
            conn.execute(
                "UPDATE normalized_events SET case_id = ? WHERE event_record_id = ?",
                (case_id, er["event_record_id"]),
            )
            conn.execute(
                """
                INSERT INTO case_event_associations (
                    association_id, case_id, record_type, record_id,
                    association_method, matching_rule_description, associated_by, associated_at
                ) VALUES (?, ?, 'normalized_event', ?, ?, ?, ?, ?)
                """,
                (
                    f"ASC-{uuid.uuid4().hex[:10].upper()}",
                    case_id,
                    er["event_record_id"],
                    "explicit_case_id" if matching_field == "case_id" else "correlation_rule_match",
                    f"Matched {matching_field} == '{target_val}'",
                    associated_by,
                    now_iso,
                ),
            )
            linked_events += 1

        if matching_field == "case_id":
            act_rows = conn.execute(
                "SELECT activity_record_id FROM analyst_activities WHERE case_id = ?",
                (target_val,),
            ).fetchall()
            for ar in act_rows:
                conn.execute(
                    """
                    INSERT INTO case_event_associations (
                        association_id, case_id, record_type, record_id,
                        association_method, matching_rule_description, associated_by, associated_at
                    ) VALUES (?, ?, 'analyst_activity', ?, 'explicit_case_id', ?, ?, ?)
                    """,
                    (
                        f"ASC-{uuid.uuid4().hex[:10].upper()}",
                        case_id,
                        ar["activity_record_id"],
                        f"Matched analyst_activities.case_id == '{target_val}'",
                        associated_by,
                        now_iso,
                    ),
                )
                linked_activities += 1

    return {
        "case_id": case_id,
        "matching_field": matching_field,
        "matching_value": target_val,
        "linked_telemetry_events": linked_events,
        "linked_analyst_activities": linked_activities,
    }


def manual_reassociate_record(
    record_type: str,
    record_id: str,
    new_case_id: str,
    reason: str,
    researcher_id: str = "researcher",
) -> Dict[str, Any]:
    """Allows manual correction of case associations with full audit logging."""
    now_iso = utc_now_iso()
    with db_manager.connection() as conn:
        c_row = conn.execute("SELECT * FROM cases WHERE case_id = ?", (new_case_id,)).fetchone()
        if not c_row:
            raise ValueError(f"Target case '{new_case_id}' does not exist.")
        if record_type == "normalized_event":
            conn.execute(
                "UPDATE normalized_events SET case_id = ? WHERE event_record_id = ?",
                (new_case_id, record_id),
            )
        elif record_type == "analyst_activity":
            conn.execute(
                "UPDATE analyst_activities SET case_id = ? WHERE activity_record_id = ?",
                (new_case_id, record_id),
            )
        else:
            raise ValueError("record_type must be 'normalized_event' or 'analyst_activity'")

        conn.execute(
            "DELETE FROM case_event_associations WHERE record_id = ?", (record_id,)
        )
        conn.execute(
            """
            INSERT INTO case_event_associations (
                association_id, case_id, record_type, record_id,
                association_method, matching_rule_description, associated_by, associated_at
            ) VALUES (?, ?, ?, ?, 'manual_researcher_assignment', ?, ?, ?)
            """,
            (
                f"ASC-{uuid.uuid4().hex[:10].upper()}",
                new_case_id,
                record_type,
                record_id,
                f"Manual correction: {reason}",
                researcher_id,
                now_iso,
            ),
        )
    db_manager.log_audit(
        actor=researcher_id,
        action_type="MANUAL_CASE_REASSOCIATION",
        entity_type=record_type,
        entity_id=record_id,
        details={"new_case_id": new_case_id, "reason": reason},
    )
    return {"record_id": record_id, "new_case_id": new_case_id, "status": "REASSOCIATED"}


def get_case_overview(case_id: str) -> Dict[str, Any]:
    with db_manager.connection() as conn:
        c = conn.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
        if not c:
            raise ValueError(f"Case '{case_id}' not found.")
        ev_cnt = conn.execute(
            "SELECT COUNT(*) AS cnt FROM normalized_events WHERE case_id = ?", (case_id,)
        ).fetchone()["cnt"]
        act_cnt = conn.execute(
            "SELECT COUNT(*) AS cnt FROM analyst_activities WHERE case_id = ?", (case_id,)
        ).fetchone()["cnt"]
        evd_cnt = conn.execute(
            "SELECT COUNT(*) AS cnt FROM evidence_references WHERE case_id = ?", (case_id,)
        ).fetchone()["cnt"]
    d = dict(c)
    d["telemetry_event_count"] = ev_cnt
    d["analyst_activity_count"] = act_cnt
    d["evidence_count"] = evd_cnt
    d["applicable_playbook_display"] = (
        f"{d['playbook_id']} ({d['playbook_version']})" if d.get("playbook_id") else "Unassigned"
    )
    return d


def list_cases() -> List[Dict[str, Any]]:
    with db_manager.connection() as conn:
        rows = conn.execute("SELECT case_id FROM cases ORDER BY case_id ASC").fetchall()
    return [get_case_overview(r["case_id"]) for r in rows]


def get_case_timeline(
    case_id: str,
    category_filter: Optional[str] = None,
    start_time_utc: Optional[str] = None,
    end_time_utc: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Builds a chronological investigation timeline strictly distinguishing:
    - security_telemetry
    - analyst_activity
    - case_status_transition
    - evidence_addition
    - escalation_event
    Never treats security telemetry events as analyst actions.
    """
    with db_manager.connection() as conn:
        ev_rows = conn.execute(
            "SELECT * FROM normalized_events WHERE case_id = ?", (case_id,)
        ).fetchall()
        act_rows = conn.execute(
            "SELECT * FROM analyst_activities WHERE case_id = ?", (case_id,)
        ).fetchall()
        evd_rows = conn.execute(
            "SELECT * FROM evidence_references WHERE case_id = ?", (case_id,)
        ).fetchall()

    timeline_items: List[Dict[str, Any]] = []
    for er in ev_rows:
        norm_fields = json.loads(er["normalized_fields_json"])
        timeline_items.append(
            {
                "timeline_id": er["event_record_id"],
                "raw_record_id": er["raw_record_id"],
                "dataset_id": er["dataset_id"],
                "timestamp_utc": er["normalized_utc_timestamp"] or "9999-12-31T23:59:59Z",
                "original_timestamp": er["original_timestamp"],
                "event_class": "security_telemetry",
                "is_analyst_action": False,
                "title": f"[{er['schema_type'].upper()}] {er['event_type'] or er['event_id'] or 'Telemetry Event'}",
                "actor_or_host": er["host"] or er["source_ip"] or er["username"] or "endpoint",
                "details": norm_fields,
            }
        )

    for ar in act_rows:
        timeline_items.append(
            {
                "timeline_id": ar["activity_record_id"],
                "raw_record_id": ar["raw_record_id"],
                "dataset_id": ar["dataset_id"],
                "timestamp_utc": ar["normalized_utc_timestamp"] or "9999-12-31T23:59:59Z",
                "original_timestamp": ar["original_timestamp"],
                "event_class": ar["timeline_category"],
                "is_analyst_action": True,
                "title": ar["activity"],
                "actor_or_host": f"{ar['analyst_id'] or 'unknown_analyst'} ({ar['analyst_role'] or 'SOC Analyst'})",
                "playbook_step_id": ar["playbook_step_id"],
                "outcome": ar["outcome"],
                "evidence_reference": ar["evidence_reference"],
                "details": json.loads(ar["original_fields_json"]),
            }
        )

    for evd in evd_rows:
        timeline_items.append(
            {
                "timeline_id": evd["evidence_id"],
                "raw_record_id": evd["source_record_id"],
                "dataset_id": None,
                "timestamp_utc": evd["collected_at"],
                "original_timestamp": evd["collected_at"],
                "event_class": "evidence_addition",
                "is_analyst_action": True,
                "title": f"Evidence Registered: {evd['title']}",
                "actor_or_host": evd["collected_by"] or "SOC Analyst",
                "evidence_reference": evd["evidence_id"],
                "details": {
                    "evidence_type": evd["evidence_type"],
                    "sha256_hash": evd["sha256_hash"],
                    "notes": evd["notes"],
                },
            }
        )

    # Filter by category and time range if specified
    if category_filter and category_filter != "all":
        timeline_items = [i for i in timeline_items if i["event_class"] == category_filter]
    if start_time_utc:
        timeline_items = [i for i in timeline_items if i["timestamp_utc"] >= start_time_utc]
    if end_time_utc:
        timeline_items = [i for i in timeline_items if i["timestamp_utc"] <= end_time_utc]

    timeline_items.sort(key=lambda x: x["timestamp_utc"])
    return {
        "case_id": case_id,
        "total_timeline_entries": len(timeline_items),
        "telemetry_entries": sum(1 for i in timeline_items if not i["is_analyst_action"]),
        "analyst_action_entries": sum(1 for i in timeline_items if i["is_analyst_action"]),
        "timeline": timeline_items,
    }
