"""
Versioned & Institutional Playbook Repository Service.
Supports both the SOC-QA Institutional Playbook Action Schema (metadata/institutional-playbook.schema.json)
and legacy benchmark playbook formats (JSON, CSV, YAML, Markdown, HTML), with strict provenance,
branch integrity validation, and a human-review status gate.
"""
import csv
import hashlib
import io
import json
import re
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.app.core.database import db_manager, utc_now_iso

VALID_INCIDENT_TYPES = {
    "phishing",
    "password_spraying",
    "suspicious_powershell",
    "persistence_antiforensics",
    "ransomware",
    "malware",
    "token_theft",
    "data_exfiltration",
    "denial_of_service",
    "cloud_iam_compromise",
    "reconnaissance_scanning",
    "public_app_exploitation",
    "privilege_escalation",
    "credential_dumping",
    "lateral_movement",
    "command_and_control",
    "confirmed_malicious_cyber_activity",
    "major_incident_response",
    "financial_sector_cyber_incident",
    "cross_organisation_incident_coordination",
    "general_incident_response",
}

VALID_NORMALIZATION_STATUSES = {
    "source_verified_not_extracted",
    "machine_extracted_unreviewed",
    "human_reviewed",
    "validated",
}

VALID_STEP_PHASES = {
    "preparation",
    "detection",
    "identification",
    "triage",
    "analysis",
    "containment",
    "eradication",
    "recovery",
    "communication",
    "post_incident",
    "coordination",
    "other",
}

VALID_PLAYBOOK_CLASSIFICATIONS = {
    "operational_soc_playbook",
    "sector_coordination_playbook",
    "reference_framework",
}


def _slugify_incident_type(raw_inc: Any) -> str:
    if isinstance(raw_inc, list):
        if not raw_inc:
            return "general_incident_response"
        first = str(raw_inc[0]).strip().lower()
    else:
        first = str(raw_inc or "").strip().lower()
    slug = re.sub(r"[^a-z0-9]+", "_", first).strip("_")
    mapping = {
        "password_spray": "password_spraying",
        "powershell": "suspicious_powershell",
        "persistence": "persistence_antiforensics",
    }
    return mapping.get(slug, slug or "general_incident_response")


def classify_institutional_playbook(institution: str, scope: str = "", source_type: str = "") -> str:
    scope_low = (scope or "").lower()
    st_low = (source_type or "").lower()
    inst_low = (institution or "").lower()
    if "not an executable playbook" in scope_low or "framework" in st_low or "standards" in st_low or inst_low in ("nist", "first", "uk ncsc"):
        return "reference_framework"
    if (
        "national-level coordination" in scope_low
        or "coordination" in scope_low
        or "national office of cyber security" in inst_low
        or "cisa" in inst_low
        or "scottish government" in inst_low
        or "acsc" in inst_low
    ):
        return "sector_coordination_playbook"
    return "operational_soc_playbook"


def validate_institutional_playbook_schema(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validates a playbook dictionary against metadata/institutional-playbook.schema.json
    and checks duplicate step IDs and predecessor/successor/branch graph integrity.
    Raises ValueError on any schema or structural violation.
    """
    required_top = ["playbook_id", "source", "title", "incident_type", "steps", "normalization"]
    missing_top = [k for k in required_top if k not in payload or payload[k] in (None, "")]
    if missing_top:
        raise ValueError(f"Playbook schema validation failed: missing required top-level fields {missing_top}")

    source = payload.get("source")
    if not isinstance(source, dict) or not source.get("source_id") or not source.get("url"):
        raise ValueError("Playbook 'source' must be an object containing non-empty 'source_id' and 'url'.")
    if not str(source.get("url", "")).startswith(("http://", "https://")):
        raise ValueError(f"Playbook source.url '{source.get('url')}' must be a valid URI.")

    norm = payload.get("normalization")
    if not isinstance(norm, dict) or norm.get("status") not in VALID_NORMALIZATION_STATUSES:
        raise ValueError(
            f"Playbook normalization.status must be one of {sorted(VALID_NORMALIZATION_STATUSES)}, got '{norm.get('status') if isinstance(norm, dict) else None}'."
        )
    if not norm.get("method"):
        raise ValueError("Playbook normalization.method is required.")

    inc_type = payload.get("incident_type")
    if isinstance(inc_type, list):
        if len(inc_type) == 0:
            raise ValueError("Playbook incident_type array cannot be empty.")
    elif not isinstance(inc_type, str) or not inc_type.strip():
        raise ValueError("Playbook incident_type must be a non-empty list or string.")

    steps = payload.get("steps")
    if not isinstance(steps, list) or len(steps) == 0:
        raise ValueError("Playbook 'steps' must be a non-empty array.")

    seen_step_ids = set()
    for idx, step in enumerate(steps, start=1):
        sid = step.get("step_id")
        if not sid or not str(sid).strip():
            raise ValueError(f"Step at index {idx} is missing 'step_id'.")
        if sid in seen_step_ids:
            raise ValueError(f"Duplicate step_id '{sid}' detected in playbook '{payload['playbook_id']}'.")
        seen_step_ids.add(sid)

        act = step.get("activity") or step.get("step_name")
        if not act:
            raise ValueError(f"Step '{sid}' is missing required 'activity' field.")

        phase = step.get("phase", "analysis")
        if phase not in VALID_STEP_PHASES:
            raise ValueError(f"Step '{sid}' has invalid phase '{phase}'. Must be one of {sorted(VALID_STEP_PHASES)}.")

        if "mandatory" in step and not isinstance(step["mandatory"], bool):
            raise ValueError(f"Step '{sid}' field 'mandatory' must be a boolean.")

        anchor = step.get("source_anchor")
        if not isinstance(anchor, dict) or not str(anchor.get("url", "")).startswith(("http://", "https://")):
            raise ValueError(f"Step '{sid}' is missing a valid 'source_anchor.url'.")

    # Second pass: verify predecessor, successor, and decision_outcomes branch integrity
    for step in steps:
        sid = step["step_id"]
        for p_id in step.get("predecessors", []) or []:
            if p_id and p_id not in seen_step_ids:
                raise ValueError(f"Step '{sid}' references non-existent predecessor '{p_id}'.")
        for s_id in step.get("successors", []) or []:
            if s_id and s_id not in seen_step_ids:
                raise ValueError(f"Step '{sid}' references non-existent successor '{s_id}'.")
        if step.get("expected_predecessor") and step["expected_predecessor"] not in seen_step_ids:
            raise ValueError(f"Step '{sid}' references non-existent expected_predecessor '{step['expected_predecessor']}'.")
        if step.get("expected_successor") and step["expected_successor"] not in seen_step_ids:
            raise ValueError(f"Step '{sid}' references non-existent expected_successor '{step['expected_successor']}'.")
        for branch in step.get("decision_outcomes", []) or []:
            for target_id in branch.get("next_step_ids", []) or []:
                if target_id not in seen_step_ids:
                    raise ValueError(
                        f"Step '{sid}' decision_outcome condition '{branch.get('condition')}' references non-existent step_id '{target_id}'."
                    )

    return {
        "valid": True,
        "playbook_id": payload["playbook_id"],
        "step_count": len(steps),
        "normalization_status": norm["status"],
    }


def normalize_playbook_to_action_schema(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalizes either a legacy benchmark playbook or an institutional playbook into the unified
    Institutional Playbook Action Schema without altering its normalization.status or inventing steps.
    """
    pb_id = payload["playbook_id"].strip()
    source_obj = payload.get("source") or {
        "source_id": f"SRC-{pb_id}",
        "url": payload.get("source_url", "https://soc-qa-intelligence.local/playbooks/" + pb_id),
        "document_title": payload.get("title", pb_id),
        "version": payload.get("version", "1.0"),
        "publication_date": None,
        "retrieval_date": utc_now_iso()[:10],
        "page_or_section": "Operational Procedure",
        "content_hash_sha256": None,
        "license_or_reuse": "Preserve attribution",
    }
    version = str(payload.get("version") or source_obj.get("version") or "1.0").strip()
    raw_inc = payload.get("incident_type", "general_incident_response")
    inc_list = raw_inc if isinstance(raw_inc, list) else [str(raw_inc)]
    inc_slug = _slugify_incident_type(raw_inc)

    institution = payload.get("institution", "SOC-QA Research Benchmark")
    scope = payload.get("scope") or payload.get("description") or f"{institution} workflow for {pb_id}"
    classification = payload.get("playbook_classification") or classify_institutional_playbook(institution, scope)

    norm_obj = payload.get("normalization") or {
        "status": "validated" if institution == "SOC-QA Research Benchmark" else "machine_extracted_unreviewed",
        "method": "Normalized via SOC-QA Playbook Repository Engine",
        "reviewer": "principal_researcher" if institution == "SOC-QA Research Benchmark" else None,
        "review_date": utc_now_iso()[:10] if institution == "SOC-QA Research Benchmark" else None,
        "confidence": 1.0 if institution == "SOC-QA Research Benchmark" else None,
        "notes": [],
    }

    normalized_steps = []
    for idx, s in enumerate(payload.get("steps", []), start=1):
        sid = s["step_id"].strip()
        act_name = (s.get("activity") or s.get("step_name") or sid).strip()
        desc = (s.get("description") or s.get("step_description") or "").strip()
        phase = s.get("phase", "analysis")
        if phase not in VALID_STEP_PHASES:
            phase = "analysis"

        # Reconcile mandatory / conditional / mandatory_status without making optional/conditional actions mandatory
        if "mandatory" in s:
            is_mand = bool(s["mandatory"])
            is_cond = bool(s.get("conditional", False))
            if is_cond:
                mand_status = "conditional"
            elif is_mand:
                mand_status = "mandatory"
            else:
                mand_status = "optional"
        else:
            mand_status = s.get("mandatory_status", "mandatory")
            is_mand = mand_status == "mandatory"
            is_cond = mand_status == "conditional"

        preds = list(s.get("predecessors") or ([] if not s.get("expected_predecessor") else [s["expected_predecessor"]]))
        succs = list(s.get("successors") or ([] if not s.get("expected_successor") else [s["expected_successor"]]))
        exp_pred = s.get("expected_predecessor") or (preds[0] if preds else None)
        exp_succ = s.get("expected_successor") or (succs[0] if succs else None)

        ev_req = s.get("evidence_required") if "evidence_required" in s else s.get("applicable_evidence_requirements", [])
        if isinstance(ev_req, str):
            ev_req = [x.strip() for x in ev_req.split(";") if x.strip()]

        alt_actions = s.get("permitted_alternative_actions", [])
        if isinstance(alt_actions, str):
            alt_actions = [x.strip() for x in alt_actions.split(";") if x.strip()]

        anchor = s.get("source_anchor") or {
            "url": source_obj["url"],
            "page": None,
            "section": f"Step {idx}",
            "quoted_excerpt": desc or act_name,
        }

        normalized_steps.append(
            {
                "step_id": sid,
                "step_order": int(s.get("step_order", idx)),
                "activity": act_name,
                "step_name": act_name,
                "description": desc,
                "step_description": desc,
                "phase": phase,
                "mandatory": is_mand,
                "conditional": is_cond,
                "mandatory_status": mand_status,
                "condition": s.get("condition"),
                "actor_role": s.get("actor_role", "SOC Analyst"),
                "predecessors": preds,
                "successors": succs,
                "expected_predecessor": exp_pred,
                "expected_successor": exp_succ,
                "decision_outcomes": s.get("decision_outcomes", []),
                "evidence_required": list(ev_req or []),
                "applicable_evidence_requirements": list(ev_req or []),
                "evidence_produced": list(s.get("evidence_produced", [])),
                "inputs": list(s.get("inputs", [])),
                "outputs": list(s.get("outputs", [])),
                "permitted_alternative_actions": list(alt_actions or []),
                "approval_requirements": s.get("approval_requirements", payload.get("approval_requirements", "")),
                "closure_requirements": s.get("closure_requirements", payload.get("closure_requirements", "")),
                "source_anchor": anchor,
                "normalization_notes": list(s.get("normalization_notes", [])),
            }
        )

    unified = {
        "playbook_id": pb_id,
        "version": version,
        "title": payload.get("title", pb_id),
        "institution": institution,
        "playbook_classification": classification,
        "incident_type": inc_list,
        "incident_type_primary": inc_slug,
        "scope": scope,
        "description": payload.get("description") or scope,
        "mitre_technique_id": payload.get("mitre_technique_id", ""),
        "approval_requirements": payload.get("approval_requirements", "Tier 2 Lead approval required for containment/isolation"),
        "closure_requirements": payload.get("closure_requirements") or "; ".join(payload.get("completion_criteria", [])) or "Verified evidence reference + documented root-cause disposition",
        "source": source_obj,
        "prerequisites": payload.get("prerequisites", []),
        "roles": payload.get("roles", []),
        "steps": normalized_steps,
        "completion_criteria": payload.get("completion_criteria", []),
        "normalization": norm_obj,
    }
    validate_institutional_playbook_schema(unified)
    return unified


def create_or_version_playbook(
    playbook_id: str,
    version: str,
    incident_type: Any,
    title: str,
    description: str,
    steps: List[Dict[str, Any]],
    mitre_technique_id: str = "",
    approval_requirements: str = "Tier 2 Lead approval required for containment/isolation",
    closure_requirements: str = "Verified evidence reference + documented root-cause disposition",
    institution: str = "SOC-QA Research Benchmark",
    playbook_classification: Optional[str] = None,
    scope: Optional[str] = None,
    source: Optional[Dict[str, Any]] = None,
    prerequisites: Optional[List[Dict[str, Any]]] = None,
    roles: Optional[List[str]] = None,
    completion_criteria: Optional[List[str]] = None,
    normalization: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Creates a new playbook or adds an immutable new version to an existing playbook.
    Never overwrites a previously saved (playbook_id, version) pair.
    Validates against the Institutional Playbook Action Schema.
    """
    inc_slug = _slugify_incident_type(incident_type)
    if inc_slug not in VALID_INCIDENT_TYPES:
        raise ValueError(
            f"Incident type '{incident_type}' (normalized: '{inc_slug}') must be one of {sorted(VALID_INCIDENT_TYPES)}"
        )
    if not steps:
        raise ValueError("Playbook must contain at least one step.")

    unified = normalize_playbook_to_action_schema(
        {
            "playbook_id": playbook_id,
            "version": version,
            "incident_type": incident_type if isinstance(incident_type, list) else [inc_slug],
            "title": title,
            "description": description,
            "scope": scope or description,
            "institution": institution,
            "playbook_classification": playbook_classification,
            "mitre_technique_id": mitre_technique_id,
            "approval_requirements": approval_requirements,
            "closure_requirements": closure_requirements,
            "source": source,
            "prerequisites": prerequisites or [],
            "roles": roles or [],
            "steps": steps,
            "completion_criteria": completion_criteria or [],
            "normalization": normalization,
        }
    )

    now_iso = utc_now_iso()
    ver_str = unified["version"]
    playbook_version_id = f"{playbook_id}@{ver_str}"

    with db_manager.connection() as conn:
        existing_ver = conn.execute(
            "SELECT playbook_version_id FROM playbook_versions WHERE playbook_id = ? AND version = ?",
            (playbook_id, ver_str),
        ).fetchone()
        if existing_ver:
            raise ValueError(
                f"Playbook '{playbook_id}' version '{ver_str}' already exists and is immutable. Create a new version tag (e.g. v1.1 or v2.0)."
            )

        pb_exists = conn.execute(
            "SELECT playbook_id FROM playbooks WHERE playbook_id = ?", (playbook_id,)
        ).fetchone()
        if not pb_exists:
            conn.execute(
                """
                INSERT INTO playbooks (
                    playbook_id, incident_type, incident_types_json, institution,
                    playbook_classification, scope, title, description, mitre_technique_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    playbook_id,
                    unified["incident_type_primary"],
                    json.dumps(unified["incident_type"]),
                    unified["institution"],
                    unified["playbook_classification"],
                    unified["scope"],
                    unified["title"],
                    unified["description"],
                    unified["mitre_technique_id"],
                    now_iso,
                ),
            )

        conn.execute(
            """
            INSERT INTO playbook_versions (
                playbook_version_id, playbook_id, version, description,
                approval_requirements, closure_requirements,
                source_metadata_json, normalization_status, normalization_metadata_json,
                prerequisites_json, roles_json, completion_criteria_json,
                is_active, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
            """,
            (
                playbook_version_id,
                playbook_id,
                ver_str,
                unified["description"],
                unified["approval_requirements"],
                unified["closure_requirements"],
                json.dumps(unified["source"]),
                unified["normalization"]["status"],
                json.dumps(unified["normalization"]),
                json.dumps(unified["prerequisites"]),
                json.dumps(unified["roles"]),
                json.dumps(unified["completion_criteria"]),
                now_iso,
            ),
        )

        for idx, step in enumerate(unified["steps"], start=1):
            conn.execute(
                """
                INSERT INTO playbook_steps (
                    step_record_id, playbook_version_id, step_id, step_order,
                    step_name, step_description, phase, mandatory_status,
                    is_conditional, condition_expression, actor_role,
                    expected_predecessor, expected_successor,
                    predecessors_json, successors_json, decision_outcomes_json,
                    permitted_alternative_actions_json, approval_requirements,
                    closure_requirements, applicable_evidence_requirements_json,
                    evidence_produced_json, inputs_json, outputs_json,
                    source_anchor_json, normalization_notes_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f"STEP-{uuid.uuid4().hex[:10].upper()}",
                    playbook_version_id,
                    step["step_id"],
                    int(step.get("step_order", idx)),
                    step["step_name"],
                    step.get("step_description", ""),
                    step.get("phase", "analysis"),
                    step.get("mandatory_status", "mandatory"),
                    1 if step.get("conditional") else 0,
                    step.get("condition"),
                    step.get("actor_role"),
                    step.get("expected_predecessor"),
                    step.get("expected_successor"),
                    json.dumps(step.get("predecessors", [])),
                    json.dumps(step.get("successors", [])),
                    json.dumps(step.get("decision_outcomes", [])),
                    json.dumps(step.get("permitted_alternative_actions", [])),
                    step.get("approval_requirements", approval_requirements),
                    step.get("closure_requirements", closure_requirements),
                    json.dumps(step.get("applicable_evidence_requirements", [])),
                    json.dumps(step.get("evidence_produced", [])),
                    json.dumps(step.get("inputs", [])),
                    json.dumps(step.get("outputs", [])),
                    json.dumps(step.get("source_anchor", {})),
                    json.dumps(step.get("normalization_notes", [])),
                ),
            )

    db_manager.log_audit(
        actor="researcher",
        action_type="PLAYBOOK_VERSION_CREATED",
        entity_type="playbook_version",
        entity_id=playbook_version_id,
        details={
            "playbook_id": playbook_id,
            "version": ver_str,
            "institution": unified["institution"],
            "normalization_status": unified["normalization"]["status"],
            "step_count": len(unified["steps"]),
        },
    )
    return get_playbook_version(playbook_id, ver_str)


def import_playbook_json(json_text: str) -> Dict[str, Any]:
    data = json.loads(json_text)
    ver = str(data.get("version") or (data.get("source") or {}).get("version") or "1.0")
    return create_or_version_playbook(
        playbook_id=data["playbook_id"],
        version=ver,
        incident_type=data["incident_type"],
        title=data.get("title", data["playbook_id"]),
        description=data.get("description") or data.get("scope") or "",
        steps=data["steps"],
        mitre_technique_id=data.get("mitre_technique_id", ""),
        approval_requirements=data.get("approval_requirements", "Tier 2 Lead approval required"),
        closure_requirements=data.get("closure_requirements", ""),
        institution=data.get("institution", "SOC-QA Research Benchmark"),
        playbook_classification=data.get("playbook_classification"),
        scope=data.get("scope"),
        source=data.get("source"),
        prerequisites=data.get("prerequisites"),
        roles=data.get("roles"),
        completion_criteria=data.get("completion_criteria"),
        normalization=data.get("normalization"),
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

    pb_dict = dict(pb)
    ver_dict = dict(ver)
    step_list = []
    for s in steps:
        sd = dict(s)
        perms = json.loads(sd.pop("permitted_alternative_actions_json", "[]") or "[]")
        ev_req = json.loads(sd.pop("applicable_evidence_requirements_json", "[]") or "[]")
        ev_prod = json.loads(sd.pop("evidence_produced_json", "[]") or "[]")
        inputs = json.loads(sd.pop("inputs_json", "[]") or "[]")
        outputs = json.loads(sd.pop("outputs_json", "[]") or "[]")
        preds = json.loads(sd.pop("predecessors_json", "[]") or "[]")
        succs = json.loads(sd.pop("successors_json", "[]") or "[]")
        dec_out = json.loads(sd.pop("decision_outcomes_json", "[]") or "[]")
        anchor = json.loads(sd.pop("source_anchor_json", "{}") or "{}")
        norm_notes = json.loads(sd.pop("normalization_notes_json", "[]") or "[]")

        sd["activity"] = sd["step_name"]
        sd["description"] = sd["step_description"]
        sd["mandatory"] = sd["mandatory_status"] == "mandatory"
        sd["conditional"] = bool(sd.pop("is_conditional", 0)) or sd["mandatory_status"] == "conditional"
        sd["condition"] = sd.pop("condition_expression", None)
        sd["permitted_alternative_actions"] = perms
        sd["applicable_evidence_requirements"] = ev_req
        sd["evidence_required"] = ev_req
        sd["evidence_produced"] = ev_prod
        sd["inputs"] = inputs
        sd["outputs"] = outputs
        sd["predecessors"] = preds
        sd["successors"] = succs
        sd["decision_outcomes"] = dec_out
        sd["source_anchor"] = anchor
        sd["normalization_notes"] = norm_notes
        step_list.append(sd)

    inc_types_list = json.loads(pb_dict.get("incident_types_json", "[]") or "[]")
    if not inc_types_list:
        inc_types_list = [pb_dict["incident_type"]]

    return {
        "playbook_id": pb_dict["playbook_id"],
        "title": pb_dict["title"],
        "institution": pb_dict.get("institution", "SOC-QA Research Benchmark"),
        "playbook_classification": pb_dict.get("playbook_classification", "operational_soc_playbook"),
        "scope": pb_dict.get("scope", pb_dict["description"]),
        "incident_type": pb_dict["incident_type"],
        "incident_types": inc_types_list,
        "mitre_technique_id": pb_dict["mitre_technique_id"],
        "version": ver_dict["version"],
        "playbook_version_id": ver_dict["playbook_version_id"],
        "description": ver_dict["description"],
        "approval_requirements": ver_dict["approval_requirements"],
        "closure_requirements": ver_dict["closure_requirements"],
        "source": json.loads(ver_dict.get("source_metadata_json", "{}") or "{}"),
        "normalization_status": ver_dict.get("normalization_status", "validated"),
        "normalization": json.loads(ver_dict.get("normalization_metadata_json", "{}") or "{}"),
        "prerequisites": json.loads(ver_dict.get("prerequisites_json", "[]") or "[]"),
        "roles": json.loads(ver_dict.get("roles_json", "[]") or "[]"),
        "completion_criteria": json.loads(ver_dict.get("completion_criteria_json", "[]") or "[]"),
        "created_at": ver_dict["created_at"],
        "steps": step_list,
    }


def list_playbooks() -> List[Dict[str, Any]]:
    with db_manager.connection() as conn:
        vers = conn.execute(
            "SELECT playbook_id, version FROM playbook_versions ORDER BY playbook_id, created_at ASC"
        ).fetchall()
    return [get_playbook_version(v["playbook_id"], v["version"]) for v in vers]


def review_institutional_playbook(
    playbook_id: str,
    version: str,
    reviewer: str,
    new_status: str,
    review_notes: str = "",
) -> Dict[str, Any]:
    """
    Human-review gate: promotes a playbook version to 'human_reviewed' or 'validated'
    after human verification of actions, branches, mandatory/conditional flags, and source anchors.
    """
    if new_status not in VALID_NORMALIZATION_STATUSES:
        raise ValueError(f"Invalid review status '{new_status}'. Must be one of {sorted(VALID_NORMALIZATION_STATUSES)}.")
    if not reviewer or not reviewer.strip():
        raise ValueError("A non-empty reviewer identifier is required to approve playbook normalization.")

    playbook_version_id = f"{playbook_id}@{version}"
    now_date = utc_now_iso()[:10]
    with db_manager.connection() as conn:
        ver = conn.execute(
            "SELECT * FROM playbook_versions WHERE playbook_version_id = ?",
            (playbook_version_id,),
        ).fetchone()
        if not ver:
            raise ValueError(f"Playbook version '{playbook_version_id}' not found.")

        norm_meta = json.loads(ver["normalization_metadata_json"] or "{}")
        old_status = ver["normalization_status"]
        norm_meta["status"] = new_status
        norm_meta["reviewer"] = reviewer.strip()
        norm_meta["review_date"] = now_date
        notes = list(norm_meta.get("notes", []))
        if review_notes:
            notes.append(f"[{now_date} {reviewer.strip()}]: {review_notes}")
        norm_meta["notes"] = notes

        conn.execute(
            """
            UPDATE playbook_versions
            SET normalization_status = ?, normalization_metadata_json = ?
            WHERE playbook_version_id = ?
            """,
            (new_status, json.dumps(norm_meta), playbook_version_id),
        )

    db_manager.log_audit(
        actor=reviewer.strip(),
        action_type="PLAYBOOK_HUMAN_REVIEW_STATUS_UPDATED",
        entity_type="playbook_version",
        entity_id=playbook_version_id,
        details={
            "previous_status": old_status,
            "new_status": new_status,
            "review_notes": review_notes,
        },
    )
    return get_playbook_version(playbook_id, version)


def seed_institutional_playbook_pack() -> Dict[str, Any]:
    """
    Registers the 20 institutional playbook sources from research/institutional_playbooks/metadata/source_manifest.json
    and imports the 3 working extractions (MS-PHISH-EXAMPLE-001, NOCS-FIN-EXAMPLE-001, CISA-FED-IR-META-001)
    preserving their exact normalization.status ('machine_extracted_unreviewed') and source anchors.
    """
    root_dir = Path(__file__).resolve().parents[4]
    pack_dir = root_dir / "research" / "institutional_playbooks"
    manifest_path = pack_dir / "metadata" / "source_manifest.json"
    norm_dir = pack_dir / "normalized"

    now_iso = utc_now_iso()
    sources_registered = 0
    if manifest_path.exists():
        manifest_entries = json.loads(manifest_path.read_text(encoding="utf-8"))
        with db_manager.connection() as conn:
            for entry in manifest_entries:
                cls_type = classify_institutional_playbook(
                    entry.get("institution", ""),
                    entry.get("normalization_status", ""),
                    entry.get("source_type", ""),
                )
                conn.execute(
                    """
                    INSERT OR REPLACE INTO institutional_playbook_sources (
                        source_id, institution, title, incident_types, format,
                        source_type, playbook_classification, url, license_or_reuse,
                        download_status, normalization_status, original_file_path,
                        content_hash_sha256, retrieval_date, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry["source_id"],
                        entry["institution"],
                        entry["title"],
                        entry["incident_types"],
                        entry["format"],
                        entry["source_type"],
                        cls_type,
                        entry["url"],
                        entry.get("license_or_reuse", ""),
                        entry["download_status"],
                        entry["normalization_status"],
                        None,
                        None,
                        "2026-11-18",
                        now_iso,
                    ),
                )
                sources_registered += 1

    # Also seed core benchmark playbooks if not yet present
    existing_vers = {p["playbook_version_id"] for p in list_playbooks()}
    pb_dir = root_dir / "research" / "playbooks"
    core_imported = []
    for fname in [
        "PB-PHISH-001_v1.0.json", "PB-SPRAY-001_v1.0.json", "PB-PSH-001_v1.0.json", "PB-PERSIST-001_v1.0.json",
        "PB-RANSOM-001_v1.0.json", "PB-MALWARE-001_v1.0.json", "PB-TOKEN-001_v1.0.json",
        "PB-EXFIL-001_v1.0.json", "PB-DOS-001_v1.0.json", "PB-CLOUD-IAM-001_v1.0.json",
        "PB-RECON-001_v1.0.json", "PB-EXPLOIT-001_v1.0.json", "PB-PRIVESC-001_v1.0.json",
        "PB-CREDDUMP-001_v1.0.json", "PB-LATERAL-001_v1.0.json", "PB-C2-001_v1.0.json",
    ]:
        fpath = pb_dir / fname
        if fpath.exists():
            data = json.loads(fpath.read_text(encoding="utf-8"))
            ver_id = f"{data['playbook_id']}@{data.get('version', '1.0')}"
            if ver_id not in existing_vers:
                import_playbook_json(fpath.read_text(encoding="utf-8"))
                existing_vers.add(ver_id)
                core_imported.append(ver_id)

    institutional_imported = []
    if norm_dir.exists():
        for jpath in sorted(norm_dir.glob("*.json")):
            data = json.loads(jpath.read_text(encoding="utf-8"))
            ver = str((data.get("source") or {}).get("version") or "1.0")
            ver_id = f"{data['playbook_id']}@{ver}"
            if ver_id not in existing_vers:
                import_playbook_json(jpath.read_text(encoding="utf-8"))
                existing_vers.add(ver_id)
                institutional_imported.append(ver_id)

    return {
        "sources_registered": sources_registered,
        "core_playbooks_imported": core_imported,
        "institutional_playbooks_imported": institutional_imported,
        "total_playbooks_in_repository": len(existing_vers),
    }


def list_institutional_sources() -> List[Dict[str, Any]]:
    with db_manager.connection() as conn:
        rows = conn.execute(
            "SELECT * FROM institutional_playbook_sources ORDER BY institution ASC, source_id ASC"
        ).fetchall()
    if not rows:
        seed_institutional_playbook_pack()
        with db_manager.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM institutional_playbook_sources ORDER BY institution ASC, source_id ASC"
            ).fetchall()
    return [dict(r) for r in rows]


PHASE_ORDER = [
    "preparation",
    "detection",
    "identification",
    "triage",
    "analysis",
    "containment",
    "eradication",
    "recovery",
    "communication",
    "coordination",
    "post_incident",
    "other",
]

PHASE_DIVERGENCE_NOTES = {
    ("PB-PHISH-001", "MS-PHISH-EXAMPLE-001", "identification"): (
        "Both playbooks initiate with email authentication and identity validation, but preserve distinct institutional scope: "
        "PB-PHISH-001 (PHISH-S1) focuses on SPF/DKIM/DMARC and Reply-To header verification on the reported message_id, "
        "whereas Microsoft Security (MSP-01) additionally requires delivery_status and recipient confirmation from Microsoft 365 message trace."
    ),
    ("PB-PHISH-001", "MS-PHISH-EXAMPLE-001", "analysis"): (
        "PB-PHISH-001 divides technical analysis into 2 mandatory steps: static/sandbox URL & attachment reputation (PHISH-S2) "
        "and SIEM proxy/DNS/authentication click search (PHISH-S3). Microsoft Security (MS-PHISH-EXAMPLE-001) structures analysis "
        "into 3 broader tenant-scoped steps: recipient distribution scoping (MSP-02), user interaction & credential exposure assessment "
        "(MSP-03), and downstream identity/endpoint/mailbox/OAuth correlation (MSP-04)."
    ),
    ("PB-PHISH-001", "MS-PHISH-EXAMPLE-001", "containment"): (
        "Critical mandatory/conditional divergence preserved without merging: PB-PHISH-001 models account isolation & Tier 2 escalation "
        "(PHISH-S4) as a CONDITIONAL step triggered only when proxy/auth logs confirm credential submission or payload execution, "
        "whereas Microsoft Security models 'Contain the threat and prevent recurrence' (MSP-05) as a MANDATORY phase step whose "
        "underlying remediation sub-actions depend on investigation findings."
    ),
    ("PB-PHISH-001", "MS-PHISH-EXAMPLE-001", "post_incident"): (
        "Institution-specific phase difference: PB-PHISH-001 defines an explicit mandatory post_incident closure step "
        "(PHISH-S5: Record Final Disposition & Close Case), whereas MS-PHISH-EXAMPLE-001 captures closure criteria inside top-level "
        "completion_criteria rather than a separate post_incident step."
    ),
}


def compare_playbooks_by_phase(
    left_playbook_id: str = "PB-PHISH-001",
    left_version: str = "1.0",
    right_playbook_id: str = "MS-PHISH-EXAMPLE-001",
    right_version: str = "1.0",
    overlapping_only: bool = False,
) -> Dict[str, Any]:
    """
    Aligns two playbooks side-by-side across canonical Action Schema phases (e.g., identification,
    analysis, containment) WITHOUT merging their distinct institutional procedures, step IDs,
    mandatory/conditional designations, or normalization statuses.
    """
    left_pb = get_playbook_version(left_playbook_id, left_version)
    right_pb = get_playbook_version(right_playbook_id, right_version)

    left_by_phase: Dict[str, List[Dict[str, Any]]] = {}
    right_by_phase: Dict[str, List[Dict[str, Any]]] = {}

    for s in left_pb["steps"]:
        ph = s.get("phase", "analysis")
        left_by_phase.setdefault(ph, []).append(s)
    for s in right_pb["steps"]:
        ph = s.get("phase", "analysis")
        right_by_phase.setdefault(ph, []).append(s)

    all_present_phases = [
        p for p in PHASE_ORDER if p in left_by_phase or p in right_by_phase
    ]
    overlapping_phases = [
        p for p in PHASE_ORDER if p in left_by_phase and p in right_by_phase
    ]
    left_only_phases = [
        p for p in PHASE_ORDER if p in left_by_phase and p not in right_by_phase
    ]
    right_only_phases = [
        p for p in PHASE_ORDER if p in right_by_phase and p not in left_by_phase
    ]

    target_phases = overlapping_phases if overlapping_only else all_present_phases
    phase_alignments = []
    for ph in target_phases:
        l_steps = left_by_phase.get(ph, [])
        r_steps = right_by_phase.get(ph, [])
        is_overlap = len(l_steps) > 0 and len(r_steps) > 0
        div_note = (
            PHASE_DIVERGENCE_NOTES.get((left_playbook_id, right_playbook_id, ph))
            or PHASE_DIVERGENCE_NOTES.get((right_playbook_id, left_playbook_id, ph))
            or (
                f"Both {left_pb['institution']} ({left_playbook_id}) and {right_pb['institution']} ({right_playbook_id}) "
                f"define {len(l_steps)} vs. {len(r_steps)} distinct step(s) in phase '{ph}' with separate institutional evidence anchors."
                if is_overlap
                else f"Phase '{ph}' is defined only in {left_playbook_id if l_steps else right_playbook_id}."
            )
        )
        phase_alignments.append(
            {
                "phase": ph,
                "is_overlapping_phase": is_overlap,
                "left_step_count": len(l_steps),
                "right_step_count": len(r_steps),
                "left_steps": l_steps,
                "right_steps": r_steps,
                "procedural_divergence_note": div_note,
            }
        )

    return {
        "comparison_mode": "non_merging_multi_institution_phase_alignment",
        "merged_procedures": False,
        "overlapping_only": overlapping_only,
        "overlapping_phases": overlapping_phases,
        "left_only_phases": left_only_phases,
        "right_only_phases": right_only_phases,
        "left_playbook": {
            "playbook_id": left_pb["playbook_id"],
            "version": left_pb["version"],
            "title": left_pb["title"],
            "institution": left_pb["institution"],
            "playbook_classification": left_pb["playbook_classification"],
            "normalization_status": left_pb["normalization_status"],
            "source": left_pb["source"],
            "total_steps": len(left_pb["steps"]),
        },
        "right_playbook": {
            "playbook_id": right_pb["playbook_id"],
            "version": right_pb["version"],
            "title": right_pb["title"],
            "institution": right_pb["institution"],
            "playbook_classification": right_pb["playbook_classification"],
            "normalization_status": right_pb["normalization_status"],
            "source": right_pb["source"],
            "total_steps": len(right_pb["steps"]),
        },
        "phase_alignments": phase_alignments,
    }


ATTACK_TYPE_EQUIVALENCE = {
    "phishing": {"phishing"},
    "password_spraying": {"password_spraying", "password_spray"},
    "suspicious_powershell": {"suspicious_powershell", "powershell"},
    "persistence_antiforensics": {
        "persistence_antiforensics",
        "confirmed_malicious_cyber_activity",
        "major_incident_response",
    },
    "ransomware": {"ransomware", "major_incident_response", "confirmed_malicious_cyber_activity"},
    "malware": {"malware", "confirmed_malicious_cyber_activity"},
    "token_theft": {"token_theft", "confirmed_malicious_cyber_activity"},
    "data_exfiltration": {"data_exfiltration", "financial_sector_cyber_incident", "major_incident_response"},
    "denial_of_service": {"denial_of_service", "major_incident_response"},
    "cloud_iam_compromise": {"cloud_iam_compromise", "confirmed_malicious_cyber_activity"},
    "reconnaissance_scanning": {"reconnaissance_scanning"},
    "public_app_exploitation": {"public_app_exploitation"},
    "privilege_escalation": {"privilege_escalation"},
    "credential_dumping": {"credential_dumping"},
    "lateral_movement": {"lateral_movement"},
    "command_and_control": {"command_and_control"},
}


def get_relevant_playbooks_for_attack_type(incident_category: str) -> List[Dict[str, Any]]:
    """
    Returns all playbook versions in the repository relevant to the given incident_category / attack type.
    Ensures institutional playbooks are seeded so every attack type has its full multi-playbook set.
    """
    all_pbs = list_playbooks()
    if len(all_pbs) < 7:
        seed_institutional_playbook_pack()
        all_pbs = list_playbooks()

    cat_slug = _slugify_incident_type(incident_category)
    target_set = ATTACK_TYPE_EQUIVALENCE.get(cat_slug, {cat_slug})

    matched = []
    for pb in all_pbs:
        pb_primary = _slugify_incident_type(pb.get("incident_type", ""))
        pb_all = {_slugify_incident_type(x) for x in pb.get("incident_types", [])}
        pb_all.add(pb_primary)
        if pb_all.intersection(target_set):
            matched.append(pb)
    return matched
