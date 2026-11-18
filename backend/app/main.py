import json
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse
from pathlib import Path
from pydantic import BaseModel

from backend.app.core.config import settings
from backend.app.core.database import db_manager, utc_now_iso
from backend.app.services.ingestion.parser import ingest_dataset_file
from backend.app.services.normalization.engine import (
    CANONICAL_SCHEMA_FIELDS,
    normalize_dataset,
    save_schema_mapping,
)
from backend.app.services.provenance.tracker import (
    export_source_manifest_csv,
    list_provenance_records,
    verify_dataset_integrity,
)
from backend.app.services.cases.manager import (
    associate_records_by_explicit_rule,
    create_or_update_case,
    get_case_overview,
    get_case_timeline,
    list_cases,
    manual_reassociate_record,
)
from backend.app.services.playbooks.repository import (
    create_or_version_playbook,
    get_playbook_version,
    import_playbook_csv,
    import_playbook_json,
    list_playbooks,
)
from backend.app.services.validation.quality import evaluate_dataset_quality
from backend.app.services.process_mining.contracts import pm4py_service
from backend.app.services.process_mining.benchmark_evaluator import (
    populate_75_case_benchmark,
    run_empirical_benchmark_evaluation,
)
from backend.app.services.ai.contracts import ai_service

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "AI-Integrated SOC Triage Quality Assurance and Playbook Conformance Framework — "
        "Research-Grade Ingestion, Normalization, Provenance, Case & Playbook Platform."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
)


class NormalizationRequest(BaseModel):
    dataset_id: str
    target_schema_type: str
    field_mapping: Dict[str, str]
    normalization_version: str = "norm-v1.0"


class SchemaMappingCreateRequest(BaseModel):
    mapping_name: str
    target_schema_type: str
    field_mapping: Dict[str, str]


class CaseCreateRequest(BaseModel):
    case_id: str
    incident_category: str
    case_status: str = "open"
    playbook_id: Optional[str] = None
    playbook_version: Optional[str] = None
    dataset_source_id: Optional[str] = None
    data_quality_status: str = "Valid"
    summary: str = ""


class CaseAssociationRequest(BaseModel):
    case_id: str
    matching_field: str = "case_id"
    matching_value: Optional[str] = None


class ManualReassociationRequest(BaseModel):
    record_type: str
    record_id: str
    new_case_id: str
    reason: str


class PlaybookCreateRequest(BaseModel):
    playbook_id: str
    version: str
    incident_type: str
    title: str
    description: str
    mitre_technique_id: str = ""
    approval_requirements: str = ""
    closure_requirements: str = ""
    steps: List[Dict[str, Any]]


class SanitizeRequest(BaseModel):
    case_id: str
    excerpts: List[Dict[str, str]]


@app.get("/api/v1/health")
def health_check():
    return {
        "status": "healthy",
        "application": settings.app_name,
        "version": settings.app_version,
        "timestamp_utc": utc_now_iso(),
    }


@app.get("/api/v1/dashboard/overview")
def get_overview_dashboard():
    """Returns strictly database-derived metrics for the Overview Dashboard."""
    with db_manager.connection() as conn:
        total_datasets = conn.execute("SELECT COUNT(*) AS c FROM datasets").fetchone()["c"]
        total_cases = conn.execute("SELECT COUNT(*) AS c FROM cases").fetchone()["c"]
        total_telemetry = conn.execute("SELECT COUNT(*) AS c FROM normalized_events").fetchone()["c"]
        total_analyst_events = conn.execute("SELECT COUNT(*) AS c FROM analyst_activities").fetchone()["c"]
        total_playbooks = conn.execute("SELECT COUNT(*) AS c FROM playbook_versions").fetchone()["c"]

        val_rows = conn.execute(
            "SELECT readiness_status, COUNT(*) AS cnt FROM validation_results GROUP BY readiness_status"
        ).fetchall()
        cat_rows = conn.execute(
            "SELECT incident_category, COUNT(*) AS cnt FROM cases GROUP BY incident_category"
        ).fetchall()
        proc_rows = conn.execute(
            "SELECT processing_status, COUNT(*) AS cnt FROM datasets GROUP BY processing_status"
        ).fetchall()
        recent_ingestions = conn.execute(
            "SELECT dataset_id, name, category, upload_date, record_count, accepted_count, rejected_count, duplicate_count, warning_count, processing_status FROM datasets ORDER BY upload_date DESC LIMIT 8"
        ).fetchall()

    return {
        "is_empty_state": (total_datasets == 0 and total_cases == 0 and total_playbooks == 0),
        "metrics": {
            "total_datasets": total_datasets,
            "total_cases": total_cases,
            "total_telemetry_records": total_telemetry,
            "total_analyst_activity_events": total_analyst_events,
            "total_playbooks": total_playbooks,
        },
        "data_validation_status": {r["readiness_status"]: r["cnt"] for r in val_rows},
        "incident_category_distribution": {r["incident_category"]: r["cnt"] for r in cat_rows},
        "dataset_processing_status": {r["processing_status"]: r["cnt"] for r in proc_rows},
        "recent_ingestion_activity": [dict(r) for r in recent_ingestions],
    }


@app.post("/api/v1/ingestion/upload")
async def upload_dataset_endpoint(
    file: UploadFile = File(...),
    category: str = Form(...),
    dataset_name: Optional[str] = Form(None),
    source_url: str = Form(""),
    source_organization: str = Form("Local Researcher Upload"),
    dataset_version: str = Form("1.0"),
    acquisition_date: Optional[str] = Form(None),
    license_info: str = Form("Academic Research / CC-BY-4.0"),
):
    content = await file.read()
    try:
        return ingest_dataset_file(
            filename=file.filename or "uploaded_file",
            content=content,
            category=category,
            dataset_name=dataset_name,
            source_url=source_url,
            source_organization=source_organization,
            dataset_version=dataset_version,
            acquisition_date=acquisition_date,
            license_info=license_info,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/v1/datasets")
def get_datasets():
    return {"datasets": list_provenance_records()}


@app.post("/api/v1/provenance/{dataset_id}/verify")
def verify_provenance_endpoint(dataset_id: str):
    try:
        return verify_dataset_integrity(dataset_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/v1/provenance/manifest/csv", response_class=PlainTextResponse)
def export_manifest_endpoint():
    return export_source_manifest_csv()


@app.get("/api/v1/normalization/schemas")
def get_canonical_schemas():
    return {"canonical_schemas": CANONICAL_SCHEMA_FIELDS}


@app.post("/api/v1/normalization/mappings")
def create_mapping_endpoint(req: SchemaMappingCreateRequest):
    try:
        return save_schema_mapping(req.mapping_name, req.target_schema_type, req.field_mapping)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/v1/normalization/run")
def run_normalization_endpoint(req: NormalizationRequest):
    try:
        return normalize_dataset(
            dataset_id=req.dataset_id,
            target_schema_type=req.target_schema_type,
            field_mapping=req.field_mapping,
            normalization_version=req.normalization_version,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/v1/cases")
def create_case_endpoint(req: CaseCreateRequest):
    try:
        return create_or_update_case(
            case_id=req.case_id,
            incident_category=req.incident_category,
            case_status=req.case_status,
            playbook_id=req.playbook_id,
            playbook_version=req.playbook_version,
            dataset_source_id=req.dataset_source_id,
            data_quality_status=req.data_quality_status,
            summary=req.summary,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/v1/cases")
def list_cases_endpoint():
    return {"cases": list_cases()}


@app.post("/api/v1/cases/associate")
def associate_case_endpoint(req: CaseAssociationRequest):
    try:
        return associate_records_by_explicit_rule(
            case_id=req.case_id,
            matching_field=req.matching_field,
            matching_value=req.matching_value,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/v1/cases/reassociate")
def manual_reassociate_endpoint(req: ManualReassociationRequest):
    try:
        return manual_reassociate_record(
            record_type=req.record_type,
            record_id=req.record_id,
            new_case_id=req.new_case_id,
            reason=req.reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/v1/cases/{case_id}/timeline")
def get_timeline_endpoint(
    case_id: str,
    category: Optional[str] = None,
    start_time_utc: Optional[str] = None,
    end_time_utc: Optional[str] = None,
):
    return get_case_timeline(case_id, category, start_time_utc, end_time_utc)


@app.post("/api/v1/playbooks")
def create_playbook_endpoint(req: PlaybookCreateRequest):
    try:
        return create_or_version_playbook(
            playbook_id=req.playbook_id,
            version=req.version,
            incident_type=req.incident_type,
            title=req.title,
            description=req.description,
            steps=req.steps,
            mitre_technique_id=req.mitre_technique_id,
            approval_requirements=req.approval_requirements,
            closure_requirements=req.closure_requirements,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/v1/playbooks/import")
async def import_playbook_file_endpoint(file: UploadFile = File(...)):
    text = (await file.read()).decode("utf-8", errors="replace")
    fname = (file.filename or "").lower()
    try:
        if fname.endswith(".json"):
            return import_playbook_json(text)
        if fname.endswith(".csv"):
            return import_playbook_csv(text)
        raise ValueError("Playbook import requires a .json or .csv file.")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/v1/playbooks")
def list_playbooks_endpoint():
    return {"playbooks": list_playbooks()}


@app.post("/api/v1/quality/{dataset_id}/evaluate")
def evaluate_quality_endpoint(dataset_id: str):
    try:
        return evaluate_dataset_quality(dataset_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/v1/process-mining/xes", response_class=PlainTextResponse)
def export_xes_endpoint():
    return pm4py_service.export_analyst_traces_to_xes()


@app.get("/api/v1/process-mining/contract")
def get_pm4py_contract():
    return pm4py_service.discover_petri_net("")


@app.get("/api/v1/ai/status")
def get_ai_status_endpoint():
    return ai_service.get_provider_status()


@app.post("/api/v1/ai/sanitize-preview")
def sanitize_preview_endpoint(req: SanitizeRequest):
    return ai_service.prepare_sanitized_case_context(req.case_id, req.excerpts)


@app.get("/", response_class=HTMLResponse)
def serve_standalone_ui():
    ui_path = Path(__file__).resolve().parents[2] / "SOC-QA_Intelligence_Standalone.html"
    if ui_path.exists():
        return HTMLResponse(content=ui_path.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>SOC-QA Intelligence API Running</h1>")


@app.post("/api/v1/process-mining/conformance/{case_id}")
def check_case_conformance_endpoint(case_id: str, playbook_version_id: Optional[str] = None):
    try:
        return pm4py_service.check_conformance_alignments(case_id, playbook_version_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/v1/ai/assess/{case_id}")
def run_ai_assessment_endpoint(case_id: str):
    try:
        return ai_service.request_structured_assessment(case_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/v1/benchmark/populate-75")
def populate_benchmark_endpoint():
    return populate_75_case_benchmark()


@app.post("/api/v1/benchmark/evaluate")
def evaluate_benchmark_endpoint():
    return run_empirical_benchmark_evaluation()
