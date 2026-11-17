#!/usr/bin/env python3
"""
Seeds the local SOC-QA Intelligence database with initial reference playbooks
(Phishing, Password Spraying T1110.003, Suspicious PowerShell T1059.001) and
sample datasets, normalized records, cases, and validation checks.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.app.services.playbooks.repository import (
    import_playbook_csv,
    import_playbook_json,
    list_playbooks,
)
from backend.app.services.ingestion.parser import ingest_dataset_file
from backend.app.services.normalization.engine import normalize_dataset
from backend.app.services.cases.manager import (
    associate_records_by_explicit_rule,
    create_or_update_case,
)
from backend.app.services.validation.quality import evaluate_dataset_quality


def seed_all():
    existing_pbs = {p["playbook_version_id"] for p in list_playbooks()}
    pb_dir = ROOT / "research" / "playbooks"
    if "PB-PHISH-001@1.0" not in existing_pbs:
        import_playbook_json((pb_dir / "PB-PHISH-001_v1.0.json").read_text(encoding="utf-8"))
    if "PB-SPRAY-001@1.0" not in existing_pbs:
        import_playbook_csv((pb_dir / "PB-SPRAY-001_v1.0.csv").read_text(encoding="utf-8"))
    if "PB-PSH-001@1.0" not in existing_pbs:
        import_playbook_json((pb_dir / "PB-PSH-001_v1.0.json").read_text(encoding="utf-8"))

    # Seed sample Phishing CSV dataset
    phish_csv = (
        "case_id,message_id,EventTime,sender,receiver,subject,body,urls,classification,source_corpus\n"
        "CASE-PHISH-001,MSG-901,2026-10-15T08:12:00+05:30,security-alert@login-micros0ft.example,cfo@corp.example,Urgent OAuth Re-Verification,Please validate your corporate credentials immediately,https://login-micros0ft.example/oauth,phishing,Nazario.csv\n"
        "CASE-PHISH-002,MSG-902,2026-10-15T09:40:00Z,billing@invoice-portal.example,ap@corp.example,Overdue Wire Remittance,Attached wire instructions require approval,https://invoice-portal.example/doc,phishing,CEAS_08.csv\n"
    ).encode("utf-8")
    ds_phish = ingest_dataset_file(
        filename="zenodo_phishing_curated_sample.csv",
        content=phish_csv,
        category="phishing_telemetry",
        dataset_name="Zenodo 8339691 Phishing Telemetry Sample",
        source_url="https://zenodo.org/records/8339691",
        source_organization="Idaho State University (Champa, Rabbi & Zibran)",
    )
    normalize_dataset(
        dataset_id=ds_phish["dataset_id"],
        target_schema_type="phishing",
        field_mapping={"EventTime": "timestamp", "receiver": "recipient", "urls": "URLs"},
    )
    evaluate_dataset_quality(ds_phish["dataset_id"])

    # Seed Analyst Activity XES dataset
    xes_bytes = """<?xml version="1.0" encoding="UTF-8" ?>
    <log xes.version="1849-2016" xmlns="http://www.xes-standard.org/">
        <trace>
            <string key="concept:name" value="CASE-PHISH-001"/>
            <event>
                <string key="concept:name" value="Ingest &amp; Parse Email Headers"/>
                <date key="time:timestamp" value="2026-10-15T02:50:00Z"/>
                <string key="org:resource" value="ANL-104"/>
                <string key="org:role" value="Tier 1 SOC Analyst"/>
                <string key="playbook_id" value="PB-PHISH-001"/>
                <string key="playbook_version" value="1.0"/>
                <string key="playbook_step_id" value="PHISH-S1"/>
                <string key="incident_type" value="phishing"/>
                <string key="evidence_reference" value="EVD-HDR-901"/>
            </event>
            <event>
                <string key="concept:name" value="Inspect Embedded URLs &amp; Attachments"/>
                <date key="time:timestamp" value="2026-10-15T02:58:00Z"/>
                <string key="org:resource" value="ANL-104"/>
                <string key="org:role" value="Tier 1 SOC Analyst"/>
                <string key="playbook_id" value="PB-PHISH-001"/>
                <string key="playbook_version" value="1.0"/>
                <string key="playbook_step_id" value="PHISH-S2"/>
                <string key="incident_type" value="phishing"/>
                <string key="evidence_reference" value="EVD-URL-901"/>
            </event>
            <event>
                <string key="concept:name" value="Isolate Compromised Account &amp; Escalate to Tier 2"/>
                <date key="time:timestamp" value="2026-10-15T03:12:00Z"/>
                <string key="org:resource" value="ANL-104"/>
                <string key="org:role" value="Tier 1 SOC Analyst"/>
                <string key="playbook_id" value="PB-PHISH-001"/>
                <string key="playbook_version" value="1.0"/>
                <string key="playbook_step_id" value="PHISH-S4"/>
                <string key="incident_type" value="phishing"/>
                <string key="evidence_reference" value="EVD-ESC-901"/>
            </event>
        </trace>
    </log>""".encode("utf-8")
    ds_xes = ingest_dataset_file(
        filename="soc_analyst_triage_traces.xes",
        content=xes_bytes,
        category="analyst_activity_logs",
        dataset_name="SOC Analyst Triage Event Log (XES)",
        source_url="https://pm4py.fit.fraunhofer.de/",
        source_organization="SOC-QA Research Lab",
    )
    normalize_dataset(
        dataset_id=ds_xes["dataset_id"],
        target_schema_type="analyst_activity",
        field_mapping={
            "concept:name": "activity",
            "time:timestamp": "timestamp",
            "org:resource": "analyst_id",
            "org:role": "analyst_role",
        },
    )
    evaluate_dataset_quality(ds_xes["dataset_id"])

    create_or_update_case(
        case_id="CASE-PHISH-001",
        incident_category="phishing",
        case_status="escalated",
        playbook_id="PB-PHISH-001",
        playbook_version="1.0",
        dataset_source_id=ds_phish["dataset_id"],
        data_quality_status="Valid",
        summary="Credential harvesting investigation (PHISH-S3 SIEM click query skipped prior to escalation).",
    )
    associate_records_by_explicit_rule("CASE-PHISH-001", "case_id")
    print("Seeded SOC-QA Intelligence workspace successfully.")


if __name__ == "__main__":
    seed_all()
