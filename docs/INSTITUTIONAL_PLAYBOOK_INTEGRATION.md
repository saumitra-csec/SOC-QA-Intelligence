# Institutional Playbook Integration & Unified Action Schema Architecture

## 1. Architecture Impact Assessment & Schema Unification Rationale

Integrating the **SOC-QA Institutional Playbook Integration Pack** (`SOC_QA_Institutional_Playbook_Integration_Pack.zip`) required evaluating whether to maintain two separate schemas or unify all playbooks under the **Institutional Playbook Action Schema** (`research/institutional_playbooks/metadata/institutional-playbook.schema.json`).

**Design Decision**: We normalized all playbooks into a **dual-compatible Unified Action Schema** (`normalize_playbook_to_action_schema` in `backend/app/services/playbooks/repository.py`) that satisfies every constraint of `institutional-playbook.schema.json` while retaining backwards-compatible fields (`step_name`, `step_description`, `mandatory_status`, `expected_predecessor`, `expected_successor`, `applicable_evidence_requirements`). This improves integration across four dimensions:
1. **Single Validation & Graph-Integrity Pipeline**: Both operational SOC benchmark playbooks (`PB-PHISH-001`, `PB-SPRAY-001`, `PB-PSH-001`, `PB-PERSIST-001`) and external institutional workflows (`MS-PHISH-EXAMPLE-001`, `NOCS-FIN-EXAMPLE-001`, `CISA-FED-IR-META-001`) undergo identical JSON Schema validation, duplicate `step_id` rejection, and branch/predecessor/successor graph verification.
2. **Strict Separation of Institutional Playbook Classes**: Every playbook is explicitly classified into one of three categories (`playbook_classification`):
   - `operational_soc_playbook`: Technical SOC analyst triage procedures (`PB-PHISH-001`, `PB-SPRAY-001`, `PB-PSH-001`, `PB-PERSIST-001`, `MS-PHISH-EXAMPLE-001`).
   - `sector_coordination_playbook`: National/sector coordination and consequence-management workflows (`NOCS-FIN-EXAMPLE-001`, `CISA-FED-IR-META-001`, Scottish Government national plans).
   - `reference_framework`: Non-executable standards and taxonomies (`NIST-800-61R3`, `FIRST-CSIRT`, `NCSC-IM`), which are blocked from step-level conformance scoring.
3. **Mandatory Human-Review Conformance Gate**: Every playbook version carries `normalization_status` (`source_verified_not_extracted`, `machine_extracted_unreviewed`, `human_reviewed`, `validated`). Working extractions from `normalized/` (`MS-PHISH-EXAMPLE-001`, `NOCS-FIN-EXAMPLE-001`, `CISA-FED-IR-META-001`) preserve `machine_extracted_unreviewed` and are blocked by `OperationalProcessMiningEngine.check_conformance_alignments` from conformance scoring until a human reviewer explicitly promotes them via `POST /api/v1/playbooks/{playbook_id}/{version}/review`.
4. **7-State Step Evaluation Semantics**: Step evaluation distinguishes `performed`, `not_performed`, `not_documented`, `not_applicable`, `out_of_order`, `evidence_insufficient`, and `condition_not_met`. Missing evidence artifacts are classified as `evidence_insufficient` rather than `not_performed`, and untriggered conditional steps (`NOCS-FIN-02`, `NOCS-FIN-05`, `PHISH-S4`, `SPRAY-S4`, `PSH-S4`) evaluate to `condition_not_met` rather than procedural failure.

## 2. Database Migration & Entity Mapping (`scripts/migrations/002_institutional_playbook_schema.sql`)

| Institutional Action Schema Field | Target Database Table & Column |
|---|---|
| `playbook_id`, `title`, `institution`, `scope` | `playbooks.playbook_id`, `title`, `institution`, `scope` |
| `incident_type` (array) | `playbooks.incident_type` (primary slug) + `playbooks.incident_types_json` |
| Derived classification | `playbooks.playbook_classification` (`operational_soc_playbook`, `sector_coordination_playbook`, `reference_framework`) |
| `source` (`source_id`, `url`, `version`, `retrieval_date`, `page_or_section`, `content_hash_sha256`, `license_or_reuse`) | `playbook_versions.source_metadata_json` + `institutional_playbook_sources` |
| `normalization` (`status`, `method`, `reviewer`, `review_date`, `confidence`, `notes`) | `playbook_versions.normalization_status` + `playbook_versions.normalization_metadata_json` |
| `prerequisites`, `roles`, `completion_criteria` | `playbook_versions.prerequisites_json`, `roles_json`, `completion_criteria_json` |
| `steps[].phase`, `mandatory`, `conditional`, `condition`, `actor_role` | `playbook_steps.phase`, `mandatory_status`, `is_conditional`, `condition_expression`, `actor_role` |
| `steps[].predecessors`, `successors`, `decision_outcomes` | `playbook_steps.predecessors_json`, `successors_json`, `decision_outcomes_json` |
| `steps[].evidence_required`, `evidence_produced`, `inputs`, `outputs` | `playbook_steps.applicable_evidence_requirements_json`, `evidence_produced_json`, `inputs_json`, `outputs_json` |
| `steps[].source_anchor` (`url`, `page`, `section`, `quoted_excerpt`), `normalization_notes` | `playbook_steps.source_anchor_json`, `normalization_notes_json` |

## 3. Source Ingestion & Normalization Status Report (20 Official & Vendor Sources + 4 Benchmark Playbooks)

| Source / Playbook ID | Institution | Classification | Ingestion Status | Normalization Status |
|---|---|---|---|---|
| `PB-PHISH-001` .. `PB-PERSIST-001` (4 Playbooks) | SOC-QA Research Benchmark | `operational_soc_playbook` | **Fully Ingested** (`research/playbooks/`) | `validated` (Conformance-Ready) |
| `MS-PHISH` (`MS-PHISH-EXAMPLE-001`) | Microsoft Security | `operational_soc_playbook` | **Partially Ingested** (5-step working extraction in `research/institutional_playbooks/normalized/MS-PHISH-EXAMPLE-001.json`; original HTML not bundled) | `machine_extracted_unreviewed` (Gated) |
| `NOCS-FIN-1.1` (`NOCS-FIN-EXAMPLE-001`) | Australian National Office of Cyber Security | `sector_coordination_playbook` | **Partially Ingested** (7-step coordination workflow in `research/institutional_playbooks/normalized/NOCS-FIN-EXAMPLE-001.json`; original PDF not bundled) | `machine_extracted_unreviewed` (Gated) |
| `CISA-FED-IR-2024` (`CISA-FED-IR-META-001`) | CISA | `sector_coordination_playbook` | **Partially Ingested** (3 high-level meta-steps in `research/institutional_playbooks/normalized/CISA-FED-IR-META-001.json`; full PDF extraction pending) | `machine_extracted_unreviewed` (Gated) |
| `SCOT-GEN-IR-2025`, `SCOT-DATA-LOSS-2.7`, `SCOT-DOS-2.7`, `SCOT-MALWARE-2.7`, `SCOT-PHISH-2.4`, `SCOT-RANSOM-2.7` | Scottish Government | `sector_coordination_playbook` | **Awaiting Original File Retrieval** (Registered in `institutional_playbook_sources`) | `source_verified_not_extracted` |
| `ACSC-IR-GUIDE-2024`, `NOCS-SECTOR-COLLECTION` | ASD / ACSC & NOCS | `sector_coordination_playbook` | **Awaiting Original File Retrieval** (Registered in `institutional_playbook_sources`) | `source_verified_not_extracted` |
| `MS-PASSWORD-SPRAY`, `MS-APP-CONSENT`, `MS-MAL-APP`, `MS-TOKEN-THEFT` | Microsoft Security | `operational_soc_playbook` | **Awaiting Original File Retrieval** (Registered in `institutional_playbook_sources`) | `source_verified_not_extracted` |
| `AWS-IR-SAMPLES`, `SPLUNK-SEC-CONTENT` | AWS & Splunk | `operational_soc_playbook` | **Awaiting Repository Archive Retrieval** (Registered in `institutional_playbook_sources`) | `source_verified_not_extracted` |
| `NIST-800-61R3`, `FIRST-CSIRT`, `NCSC-IM` | NIST, FIRST, UK NCSC | `reference_framework` | **Reference Taxonomy Only** (Not executable playbooks; registered in `institutional_playbook_sources`) | `source_verified_not_extracted` |
