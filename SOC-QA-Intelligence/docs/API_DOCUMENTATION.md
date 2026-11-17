# SOC-QA Intelligence — REST API Documentation

Base URL: `http://localhost:8000/api/v1` (Interactive OpenAPI / Swagger UI available at `http://localhost:8000/docs`)

## Core Endpoints
| Method | Endpoint | Module | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/health` | Foundation | Returns service health and UTC timestamp. |
| `GET` | `/api/v1/dashboard/overview` | Dashboard | Returns real database counts, validation breakdown, category distribution, and empty-state flag. |
| `POST` | `/api/v1/ingestion/upload` | Module 1 | Multipart upload of `.csv`, `.json`, `.jsonl`/`.ndjson`, or `.xes` files with manual category classification and SHA-256 calculation. |
| `GET` | `/api/v1/datasets` | Module 3 | Lists all ingested datasets and immutable provenance records. |
| `POST` | `/api/v1/provenance/{dataset_id}/verify` | Module 3 | Recalculates on-disk SHA-256 digest and verifies against stored provenance hash. |
| `GET` | `/api/v1/provenance/manifest/csv` | Module 3 | Exports the complete source provenance manifest as CSV. |
| `GET` | `/api/v1/normalization/schemas` | Module 2 | Lists canonical target schemas and supported fields. |
| `POST` | `/api/v1/normalization/mappings` | Module 2 | Saves a reusable source-to-normalized field mapping profile. |
| `POST` | `/api/v1/normalization/run` | Module 2 | Runs non-destructive field mapping and UTC ISO 8601 timestamp normalization. |
| `GET` | `/api/v1/cases` | Module 4 | Lists all investigation cases with telemetry, analyst activity, and evidence counts. |
| `POST` | `/api/v1/cases` | Module 4 | Creates or updates an investigation case pinned to a specific playbook version. |
| `POST` | `/api/v1/cases/associate` | Module 4 | Associates records with a case using explicit identifiers or deterministic rules. |
| `POST` | `/api/v1/cases/reassociate` | Module 4 | Manually corrects a record's case association with audit logging. |
| `GET` | `/api/v1/cases/{case_id}/timeline` | Module 4 | Retrieves the chronological case timeline separating telemetry from analyst actions. |
| `GET` | `/api/v1/playbooks` | Module 5 | Lists all version-controlled reference playbooks and ordered steps. |
| `POST` | `/api/v1/playbooks` | Module 5 | Creates a new playbook or adds an immutable new version tag. |
| `POST` | `/api/v1/playbooks/import` | Module 5 | Imports a reference playbook from JSON or CSV. |
| `POST` | `/api/v1/quality/{dataset_id}/evaluate` | Module 6 | Evaluates 9 data quality dimensions and generates a readiness report. |
| `GET` | `/api/v1/process-mining/xes` | Phase 6 | Exports normalized `analyst_activities` (excluding raw telemetry) as IEEE 1849-2016 XES. |
| `GET` | `/api/v1/process-mining/contract` | Phase 6 | Returns the PM4Py service contract and readiness guardrails. |
| `GET` | `/api/v1/ai/status` | Phase 6 | Returns the vendor-agnostic Explainable AI provider configuration status. |
| `POST` | `/api/v1/ai/sanitize-preview` | Phase 6 | Tests untrusted email/log excerpts against the prompt-injection sanitizer. |
