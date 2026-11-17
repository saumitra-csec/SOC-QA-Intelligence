# SOC-QA Intelligence — System & Research Architecture

## 1. Architectural Vision
**SOC-QA Intelligence** (*AI-Integrated SOC Triage Quality Assurance and Playbook Conformance Framework*) is a modular, research-grade full-stack platform designed to investigate **SOC Playbook Drift: Written Procedure vs. Actual Analyst Practice**.

The architecture strictly separates three analytical dimensions so that they are never collapsed into an opaque analyst score:
1. **Process Conformance**: Alignment between observed analyst workflow traces (`analyst_activities`) and version-pinned reference playbooks (`playbook_versions` / `playbook_steps`).
2. **Investigation Quality**: Sufficiency of collected evidence (`evidence_references`) and validity of escalation/closure decisions.
3. **Documentation Quality**: Completeness of recorded investigation steps and artefact references (`validation_results`), explicitly recognizing that a missing event in a log may represent an observability or documentation gap rather than analyst error.

## 2. Layered Full-Stack Design
- **Presentation Layer (`frontend/`)**: React 18, TypeScript, Vite, Tailwind CSS, Recharts, and Lucide icons configured with a 13-view persistent research workstation sidebar.
- **API & Domain Service Layer (`backend/app/`)**: Python 3.11+ FastAPI service organized into six active core modules and two future-ready analytical contracts:
  - `services/ingestion/`: Multi-format adapter supporting `.csv`, `.json`, `.jsonl`/`.ndjson`, and IEEE 1849-2016 `.xes` event logs with automatic encoding detection (`chardet`), duplicate detection, and malformed row isolation.
  - `services/normalization/`: Configurable schema mapping engine across five canonical schemas (`analyst_activity`, `phishing`, `password_spray`, `powershell`, `security_telemetry`) with ISO 8601 UTC timestamp normalization and strict non-fabrication guarantees.
  - `services/provenance/`: Cryptographic SHA-256 integrity verification (`hashlib`) and CSV source manifest export.
  - `services/cases/`: Case management, explicit identifier & deterministic rule-based event association, manual re-association audit trail, and chronological investigation timeline builder.
  - `services/playbooks/`: Immutable version-controlled playbook repository supporting CSV and JSON imports.
  - `services/validation/`: Nine-dimension Data Quality & Research Readiness engine.
  - `services/process_mining/`: Service contract (`PM4PyServiceContract`) and XES trace exporter operating exclusively on `analyst_activities` (never raw security telemetry) with reference to [PM4Py Core](https://github.com/eon-collective/pm4py-core).
  - `services/ai/`: Vendor-agnostic Explainable AI contract (`ExplainableAIProviderContract`) with untrusted log/email prompt-injection sanitization and mandatory human validation (`PENDING_HUMAN_REVIEW`).
- **Persistence Layer**: Normalized 27-table relational schema supporting PostgreSQL 15 (`docker-compose.yml`) and automatic local SQLite3 fallback (`data/socqa_research.db`) when Docker is unavailable.

## 3. Reference Repository Analysis & Adopted Concepts
In accordance with Section 15 of the research specification, the following open-source repositories and standards were inspected prior to designing the service contracts:
- **PM4Py Core** ([github.com/eon-collective/pm4py-core](https://github.com/eon-collective/pm4py-core) & [PM4Py XES Importer Documentation](https://pm4py-source.readthedocs.io/en/latest/_modules/pm4py/objects/log/importer/xes/variants/iterparse_mem_compressed.html)): Adopted IEEE 1849-2016 XES standard attributes (`concept:name`, `time:timestamp`, `org:resource`, `org:role`) for trace export and ingestion.
- **PM4PY-UI & Algorithmic Process Mining** ([GitHub Conformance Checking Topic](https://github.com/topics/conformance-checking) listing `GroveGuard/PM4PY-UI` and `Ashok007-cmd/algorithmic-process-mining`): Adopted separation between event log discovery and token-based/alignment conformance checking contracts without hardcoding synthetic fitness figures.
- **SOCTalk** ([github.com/soctalk/soctalk](https://github.com/soctalk/soctalk), Apache-2.0): Adopted the human-gated review queue pattern (`PENDING_HUMAN_REVIEW` in `ai_assessments` and append-only `audit_records`) and multi-provider LLM abstraction (Anthropic, OpenAI-compatible, or local Ollama).
- **Automatic Case Investigator (ACI)** ([github.com/acezxn](https://github.com/acezxn) pinning `Automatic-Case-Investigator/ACI`): Adopted on-premise investigation context packaging that restricts LLM context strictly to case-relevant records.
- **SOC-Lab-Playbooks** ([github.com/SecurityWithAdarsh/SOC-Lab-Playbooks](https://github.com/SecurityWithAdarsh/SOC-Lab-Playbooks)): Adopted NIST SP 800-61 Rev. 2 lifecycle staging (Detection/Triage -> Enrichment -> Containment/Escalation -> Closure) and MITRE ATT&CK mapping (`T1566`, `T1110.003`, `T1059.001`) in our versioned reference playbooks.
- **TheHive Project** ([github.com/thehive-project/thehive](https://github.com/thehive-project/thehive)): Adopted explicit observable/evidence reference linking (`evidence_references`) distinct from raw alert events.
