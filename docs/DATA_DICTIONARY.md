# SOC-QA Intelligence — Data Dictionary & Relational Schema

## 1. Canonical Normalized Schemas (Module 2)

### 1.1 Analyst Activity Events (`analyst_activities`)
| Field Name | Type | Requirement | Description |
| :--- | :--- | :--- | :--- |
| `case_id` | `TEXT` | Mandatory | Unique investigation identifier (`CASE-XXX`) linking the activity to a case. |
| `activity` | `TEXT` | Mandatory | Standardized analyst action name (`concept:name` in XES). |
| `timestamp` | `TEXT` | Mandatory | Normalized UTC ISO 8601 timestamp (`YYYY-MM-DDTHH:MM:SSZ`). |
| `incident_type` | `TEXT` | Mandatory | Incident stratum (`phishing`, `password_spraying`, `suspicious_powershell`). |
| `analyst_id` | `TEXT` | Mandatory | Pseudonymous analyst identifier (`org:resource`). |
| `analyst_role` | `TEXT` | Optional | Analyst tier/role (`Tier 1 SOC Analyst`, `Tier 2 Incident Responder`). |
| `playbook_id` | `TEXT` | Optional | Reference playbook identifier (`PB-PHISH-001`, `PB-SPRAY-001`, `PB-PSH-001`). |
| `playbook_version` | `TEXT` | Optional | Immutable version string (`1.0`, `1.1`). |
| `playbook_step_id` | `TEXT` | Optional | Step identifier (`PHISH-S1`, `SPRAY-S2`, `PSH-S3`). |
| `activity_status` | `TEXT` | Optional | Execution status (`completed`, `in_progress`, `skipped_justified`). |
| `outcome` | `TEXT` | Optional | Documented outcome of the step. |
| `source_system` | `TEXT` | Optional | Originating SOAR/ticketing platform. |
| `evidence_reference` | `TEXT` | Optional | Pointer to supporting record in `evidence_references`. |

### 1.2 Phishing Telemetry (`normalized_events` — `schema_type = 'phishing'`)
Designed for compatibility with the [Zenodo Phishing Email Curated Datasets (Record 8339691)](https://zenodo.org/records/8339691) ([HuggingFace Cleaned Release README](https://huggingface.co/datasets/it4lia/PhishingEmailCuratedDatasets_Cleaned/blob/main/README.md)):
- Retained fields: `message_id`, `timestamp`, `sender`, `recipient`, `reply_to`, `subject`, `body`, `URLs`, `attachment_names`, `attachment_hashes`, `classification`, `source_corpus` (`CEAS_08.csv`, `Nazario.csv`, `Nigerian_Fraud.csv`, `SpamAssasin.csv`, `TREC_05.csv`–`TREC_07.csv`, `Enron.csv`, `Ling.csv`).

### 1.3 Password-Spray Telemetry (`normalized_events` — `schema_type = 'password_spray'`)
Designed for compatibility with [Splunk Attack Data](https://github.com/splunk/attack_data) MITRE ATT&CK `T1110.003`:
- Retained fields: `timestamp`, `event_id`, `source_ip`, `target_account`, `host`, `logon_type`, `authentication_result`, `failure_reason`, `application`, `tenant`, `user_agent`.

### 1.4 Suspicious PowerShell Telemetry (`normalized_events` — `schema_type = 'powershell'`)
Designed for compatibility with [Splunk Attack Data](https://github.com/splunk/attack_data), [OTRF Security Datasets](https://github.com/OTRF/Security-Datasets), [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), and [Microsoft PowerShell Logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.6) MITRE ATT&CK `T1059.001`:
- Retained fields: `timestamp`, `host`, `user`, `event_id`, `process_image`, `parent_image`, `command_line`, `process_id`, `script_block_id`, `script_block_text`, `file_path`, `file_hash`, `destination_ip`, `destination_domain`, `destination_port`.

## 2. Relational Database Entities (27 Tables)
- **Active Core Tables (19)**: `users`, `datasets`, `dataset_files`, `source_manifest`, `schema_mappings`, `ingestion_jobs`, `raw_records`, `normalized_events`, `cases`, `case_event_associations`, `analyst_activities`, `evidence_references`, `playbooks`, `playbook_versions`, `playbook_steps`, `ground_truth_labels`, `validation_results`, `processing_runs`, `audit_records`.
- **Future Research Tables (8)**: `conformance_results`, `deviation_findings`, `ai_assessments`, `ai_model_registry`, `prompt_versions`, `human_review_records`, `research_experiments`, `evaluation_metrics`.
