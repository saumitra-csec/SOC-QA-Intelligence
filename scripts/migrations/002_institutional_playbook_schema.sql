-- Migration 002: Institutional Playbook Action Schema & Source Register
ALTER TABLE playbooks ADD COLUMN incident_types_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE playbooks ADD COLUMN institution TEXT NOT NULL DEFAULT 'SOC-QA Research Benchmark';
ALTER TABLE playbooks ADD COLUMN playbook_classification TEXT NOT NULL DEFAULT 'operational_soc_playbook';
ALTER TABLE playbooks ADD COLUMN scope TEXT NOT NULL DEFAULT '';

ALTER TABLE playbook_versions ADD COLUMN source_metadata_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE playbook_versions ADD COLUMN normalization_status TEXT NOT NULL DEFAULT 'validated';
ALTER TABLE playbook_versions ADD COLUMN normalization_metadata_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE playbook_versions ADD COLUMN prerequisites_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE playbook_versions ADD COLUMN roles_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE playbook_versions ADD COLUMN completion_criteria_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE playbook_steps ADD COLUMN phase TEXT NOT NULL DEFAULT 'analysis';
ALTER TABLE playbook_steps ADD COLUMN is_conditional INTEGER NOT NULL DEFAULT 0;
ALTER TABLE playbook_steps ADD COLUMN condition_expression TEXT;
ALTER TABLE playbook_steps ADD COLUMN actor_role TEXT;
ALTER TABLE playbook_steps ADD COLUMN predecessors_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE playbook_steps ADD COLUMN successors_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE playbook_steps ADD COLUMN decision_outcomes_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE playbook_steps ADD COLUMN evidence_produced_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE playbook_steps ADD COLUMN inputs_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE playbook_steps ADD COLUMN outputs_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE playbook_steps ADD COLUMN source_anchor_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE playbook_steps ADD COLUMN normalization_notes_json TEXT NOT NULL DEFAULT '[]';

CREATE TABLE IF NOT EXISTS institutional_playbook_sources (
    source_id TEXT PRIMARY KEY,
    institution TEXT NOT NULL,
    title TEXT NOT NULL,
    incident_types TEXT NOT NULL,
    format TEXT NOT NULL,
    source_type TEXT NOT NULL,
    playbook_classification TEXT NOT NULL,
    url TEXT NOT NULL,
    license_or_reuse TEXT,
    download_status TEXT NOT NULL,
    normalization_status TEXT NOT NULL,
    original_file_path TEXT,
    content_hash_sha256 TEXT,
    retrieval_date TEXT,
    created_at TEXT NOT NULL
);
