import csv
import io
import json
import uuid
from typing import Any, Dict, List

from backend.app.core.database import db_manager, utc_now_iso

VALID_INCIDENT_TYPES = {"phishing", "password_spraying", "suspicious_powershell"}


def create_or_version_playbook(
    playbook_id: str,
    version: str,
    incident_type: str,
    title: str,
    description: str,
    steps: List[Dict[str, Any]],
    mitre_technique_id: str = "",
    approval_requirements: str = "Tier 2 Lead approval required for containment/isolation",
    closure_requirements: str = "Verified evidence reference + documented root-cause disposition",
) -> Dict[str, Any]:
    """
    Creates a new playbook or adds an immutable new version to an existing playbook.
    Never overwrites a previously saved (playbook_id, version) pair.
    """
    if incident_type not in VALID_INCIDENT_TYPES:
        raise ValueError(
            f"Incident type '{incident_type}' must be one of {sorted(VALID_INCIDENT_TYPES)}"
        )
    if not steps:
        raise ValueError("Playbook must contain at least one step.")

    now_iso = utc_now_iso()
    playbook_version_id = f"{playbook_id}@{version}"

    with db_manager.connection() as conn:
        existing_ver = conn.execute(
            "SELECT playbook_version_id FROM playbook_versions WHERE playbook_id = ? AND version = ?",
            (playbook_id, version),
        ).fetchone()
        if existing_ver:
            raise ValueError(
                f"Playbook '{playbook_id}' version '{version}' already exists and is immutable. Create a new version tag (e.g. v1.1 or v2.0)."
            )

        pb_exists = conn.execute(
            "SELECT playbook_id FROM playbooks WHERE playbook_id = ?", (playbook_id,)
        ).fetchone()
        if not pb_exists:
            conn.execute(
                """
                INSERT INTO playbooks (playbook_id, incident_type, title, description, mitre_technique_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (playbook_id, incident_type, title, description, mitre_technique_id, now_iso),
            )

        conn.execute(
            """
            INSERT INTO playbook_versions (
                playbook_version_id, playbook_id, version, description,
                approval_requirements, closure_requirements, is_active, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, 1, ?)
            """,
            (
                playbook_version_id,
                playbook_id,
                version,
                description,
                approval_requirements,
                closure_requirements,
                now_iso,
            ),
        )

        for idx, step in enumerate(steps, start=1):
            alt_actions = step.get("permitted_alternative_actions", [])
            if isinstance(alt_actions, str):
                alt_actions = [s.strip() for s in alt_actions.split(";") if s.strip()]
            evd_reqs = step.get("applicable_evidence_requirements", [])
            if isinstance(evd_reqs, str):
                evd_reqs = [s.strip() for s in evd_reqs.split(";") if s.strip()]

            conn.execute(
                """
                INSERT INTO playbook_steps (
                    step_record_id, playbook_version_id, step_id, step_order,
                    step_name, step_description, mandatory_status,
                    expected_predecessor, expected_successor,
                    permitted_alternative_actions_json, approval_requirements,
                    closure_requirements, applicable_evidence_requirements_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f"STEP-{uuid.uuid4().hex[:10].upper()}",
                    playbook_version_id,
                    step["step_id"],
                    int(step.get("step_order", idx)),
                    step["step_name"],
                    step.get("step_description", ""),
                    step.get("mandatory_status", "mandatory"),
                    step.get("expected_predecessor"),
                    step.get("expected_successor"),
                    json.dumps(alt_actions),
                    step.get("approval_requirements", approval_requirements),
                    step.get("closure_requirements", closure_requirements),
                    json.dumps(evd_reqs),
                ),
            )

    db_manager.log_audit(
        actor="researcher",
        action_type="PLAYBOOK_VERSION_CREATED",
        entity_type="playbook_version",
        entity_id=playbook_version_id,
        details={"playbook_id": playbook_id, "version": version, "step_count": len(steps)},
    )
    return get_playbook_version(playbook_id, version)


def import_playbook_json(json_text: str) -> Dict[str, Any]:
    data = json.loads(json_text)
    return create_or_version_playbook(
        playbook_id=data["playbook_id"],
        version=data["version"],
        incident_type=data["incident_type"],
        title=data.get("title", data["playbook_id"]),
        description=data.get("description", ""),
        steps=data["steps"],
        mitre_technique_id=data.get("mitre_technique_id", ""),
        approval_requirements=data.get("approval_requirements", ""),
        closure_requirements=data.get("closure_requirements", ""),
    )


def import_playbook_csv(csv_text: str) -> Dict[str, Any]:
    reader = list(csv.DictReader(io.StringIO(csv_text)))
    if not reader:
        raise ValueError("CSV playbook file contains no step rows.")
    first = reader[0]
    steps = []
    for idx, row in enumerate(reader, start=1):
        steps.append(
            {
                "step_id": row["step_id"].strip(),
                "step_order": idx,
                "step_name": row["step_name"].strip(),
                "step_description": row.get("step_description", "").strip(),
                "mandatory_status": row.get("mandatory_status", "mandatory").strip(),
                "expected_predecessor": row.get("expected_predecessor", "").strip() or None,
                "expected_successor": row.get("expected_successor", "").strip() or None,
                "permitted_alternative_actions": row.get("permitted_alternative_actions", ""),
                "approval_requirements": row.get("approval_requirements", ""),
                "closure_requirements": row.get("closure_requirements", ""),
                "applicable_evidence_requirements": row.get("applicable_evidence_requirements", ""),
            }
        )
    return create_or_version_playbook(
        playbook_id=first["playbook_id"].strip(),
        version=first["version"].strip(),
        incident_type=first["incident_type"].strip(),
        title=first.get("title", first["playbook_id"]).strip(),
        description=first.get("description", "Imported CSV Reference Playbook").strip(),
        steps=steps,
        mitre_technique_id=first.get("mitre_technique_id", "").strip(),
    )


def get_playbook_version(playbook_id: str, version: str) -> Dict[str, Any]:
    playbook_version_id = f"{playbook_id}@{version}"
    with db_manager.connection() as conn:
        pb = conn.execute(
            "SELECT * FROM playbooks WHERE playbook_id = ?", (playbook_id,)
        ).fetchone()
        ver = conn.execute(
            "SELECT * FROM playbook_versions WHERE playbook_version_id = ?",
            (playbook_version_id,),
        ).fetchone()
        if not pb or not ver:
            raise ValueError(f"Playbook version '{playbook_version_id}' not found.")
        steps = conn.execute(
            "SELECT * FROM playbook_steps WHERE playbook_version_id = ? ORDER BY step_order ASC",
            (playbook_version_id,),
        ).fetchall()

    step_list = []
    for s in steps:
        sd = dict(s)
        sd["permitted_alternative_actions"] = json.loads(
            sd.pop("permitted_alternative_actions_json", "[]")
        )
        sd["applicable_evidence_requirements"] = json.loads(
            sd.pop("applicable_evidence_requirements_json", "[]")
        )
        step_list.append(sd)

    return {
        "playbook_id": pb["playbook_id"],
        "title": pb["title"],
        "incident_type": pb["incident_type"],
        "mitre_technique_id": pb["mitre_technique_id"],
        "version": ver["version"],
        "playbook_version_id": ver["playbook_version_id"],
        "description": ver["description"],
        "approval_requirements": ver["approval_requirements"],
        "closure_requirements": ver["closure_requirements"],
        "created_at": ver["created_at"],
        "steps": step_list,
    }


def list_playbooks() -> List[Dict[str, Any]]:
    with db_manager.connection() as conn:
        vers = conn.execute(
            "SELECT playbook_id, version FROM playbook_versions ORDER BY playbook_id, created_at ASC"
        ).fetchall()
    return [get_playbook_version(v["playbook_id"], v["version"]) for v in vers]
