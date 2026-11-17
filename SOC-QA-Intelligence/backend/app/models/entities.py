"""
Normalized Relational Schema for SOC-QA Intelligence (27 Entities: 19 Active + 8 Future Research Entities).
Compatible with both PostgreSQL (DDL exported to scripts/init_postgres.sql) and SQLite3 local research engine.
"""

SCHEMA_MIGRATION_VERSION = "2026_11_17_001_initial_research_schema"

RELATIONAL_TABLES_DDL = [
    # 0. schema_migrations (Migration version tracking)
    """
    CREATE TABLE IF NOT EXISTS schema_migrations (
        version TEXT PRIMARY KEY,
        applied_at TEXT NOT NULL,
        description TEXT NOT NULL
    );
    """,
    # 1. users (Authentication & Role-Based Authorization architecture)
    """
    CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('principal_researcher', 'soc_auditor', 'tier1_analyst', 'tier2_analyst', 'readonly_reviewer')),
        created_at TEXT NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1
    );
    """,
    # 2. datasets (High-level dataset metadata & categorization)
    """
    CREATE TABLE IF NOT EXISTS datasets (
        dataset_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        category TEXT NOT NULL CHECK (category IN (
            'phishing_telemetry',
            'password_spray_telemetry',
            'suspicious_powershell_telemetry',
            'analyst_activity_logs',
            'case_metadata',
            'reference_playbooks',
            'evidence_metadata',
            'ground_truth_annotations'
        )),
        source_url TEXT,
        source_organization TEXT,
        dataset_version TEXT NOT NULL DEFAULT '1.0',
        acquisition_date TEXT,
        upload_date TEXT NOT NULL,
        license_info TEXT,
        processing_status TEXT NOT NULL CHECK (processing_status IN ('uploaded', 'inspected', 'normalized', 'validated', 'rejected')),
        normalization_version TEXT DEFAULT 'norm-v1.0',
        record_count INTEGER NOT NULL DEFAULT 0,
        accepted_count INTEGER NOT NULL DEFAULT 0,
        rejected_count INTEGER NOT NULL DEFAULT 0,
        duplicate_count INTEGER NOT NULL DEFAULT 0,
        warning_count INTEGER NOT NULL DEFAULT 0
    );
    """,
    # 3. dataset_files (Immutable raw file storage metadata & SHA-256 digest)
    """
    CREATE TABLE IF NOT EXISTS dataset_files (
        file_id TEXT PRIMARY KEY,
        dataset_id TEXT NOT NULL,
        original_filename TEXT NOT NULL,
        stored_raw_path TEXT NOT NULL,
        file_format TEXT NOT NULL CHECK (file_format IN ('csv', 'json', 'jsonl', 'ndjson', 'xes')),
        file_size_bytes INTEGER NOT NULL,
        encoding TEXT NOT NULL DEFAULT 'utf-8',
        sha256_checksum TEXT NOT NULL,
        uploaded_at TEXT NOT NULL,
        FOREIGN KEY (dataset_id) REFERENCES datasets(dataset_id) ON DELETE CASCADE
    );
    """,
    # 4. source_manifest (Immutable provenance manifest records)
    """
    CREATE TABLE IF NOT EXISTS source_manifest (
        manifest_id TEXT PRIMARY KEY,
        dataset_id TEXT NOT NULL UNIQUE,
        original_filename TEXT NOT NULL,
        original_source_url TEXT,
        source_organization TEXT,
        dataset_version TEXT NOT NULL,
        acquisition_date TEXT,
        upload_date TEXT NOT NULL,
        file_format TEXT NOT NULL,
        file_size_bytes INTEGER NOT NULL,
        license_information TEXT,
        sha256_checksum TEXT NOT NULL,
        processing_status TEXT NOT NULL,
        normalization_version TEXT NOT NULL,
        associated_case_ids_json TEXT NOT NULL DEFAULT '[]',
        last_verified_at TEXT,
        integrity_status TEXT NOT NULL DEFAULT 'VERIFIED',
        FOREIGN KEY (dataset_id) REFERENCES datasets(dataset_id) ON DELETE CASCADE
    );
    """,
    # 5. schema_mappings (Configurable, reusable source-to-normalized field mappings)
    """
    CREATE TABLE IF NOT EXISTS schema_mappings (
        mapping_id TEXT PRIMARY KEY,
        mapping_name TEXT NOT NULL UNIQUE,
        target_schema_type TEXT NOT NULL CHECK (target_schema_type IN (
            'analyst_activity',
            'security_telemetry',
            'phishing',
            'password_spray',
            'powershell'
        )),
        mapping_json TEXT NOT NULL,
        created_by TEXT,
        created_at TEXT NOT NULL
    );
    """,
    # 6. ingestion_jobs (Execution & status tracking for file ingestion runs)
    """
    CREATE TABLE IF NOT EXISTS ingestion_jobs (
        job_id TEXT PRIMARY KEY,
        dataset_id TEXT NOT NULL,
        file_id TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'failed')),
        total_records INTEGER NOT NULL DEFAULT 0,
        accepted_records INTEGER NOT NULL DEFAULT 0,
        rejected_records INTEGER NOT NULL DEFAULT 0,
        duplicate_records INTEGER NOT NULL DEFAULT 0,
        warning_records INTEGER NOT NULL DEFAULT 0,
        inferred_timestamp_cols_json TEXT NOT NULL DEFAULT '[]',
        inferred_case_id_cols_json TEXT NOT NULL DEFAULT '[]',
        detected_fields_json TEXT NOT NULL DEFAULT '[]',
        missing_fields_json TEXT NOT NULL DEFAULT '[]',
        error_summary TEXT,
        started_at TEXT NOT NULL,
        completed_at TEXT,
        FOREIGN KEY (dataset_id) REFERENCES datasets(dataset_id) ON DELETE CASCADE,
        FOREIGN KEY (file_id) REFERENCES dataset_files(file_id) ON DELETE CASCADE
    );
    """,
    # 7. raw_records (Preserved original source records with row index & raw JSON payload)
    """
    CREATE TABLE IF NOT EXISTS raw_records (
        raw_record_id TEXT PRIMARY KEY,
        dataset_id TEXT NOT NULL,
        row_index INTEGER NOT NULL,
        raw_payload_json TEXT NOT NULL,
        record_hash TEXT NOT NULL,
        is_malformed INTEGER NOT NULL DEFAULT 0,
        is_duplicate INTEGER NOT NULL DEFAULT 0,
        parse_warnings_json TEXT NOT NULL DEFAULT '[]',
        ingested_at TEXT NOT NULL,
        FOREIGN KEY (dataset_id) REFERENCES datasets(dataset_id) ON DELETE CASCADE
    );
    """,
    # 8. playbooks (High-level reference playbook identity)
    """
    CREATE TABLE IF NOT EXISTS playbooks (
        playbook_id TEXT PRIMARY KEY,
        incident_type TEXT NOT NULL CHECK (incident_type IN ('phishing', 'password_spraying', 'suspicious_powershell', 'persistence_antiforensics')),
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        mitre_technique_id TEXT,
        created_at TEXT NOT NULL
    );
    """,
    # 9. playbook_versions (Immutable version control for playbooks)
    """
    CREATE TABLE IF NOT EXISTS playbook_versions (
        playbook_version_id TEXT PRIMARY KEY,
        playbook_id TEXT NOT NULL,
        version TEXT NOT NULL,
        description TEXT NOT NULL,
        approval_requirements TEXT,
        closure_requirements TEXT,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        UNIQUE(playbook_id, version),
        FOREIGN KEY (playbook_id) REFERENCES playbooks(playbook_id) ON DELETE RESTRICT
    );
    """,
    # 10. playbook_steps (Ordered & conditional steps belonging to a specific playbook_version)
    """
    CREATE TABLE IF NOT EXISTS playbook_steps (
        step_record_id TEXT PRIMARY KEY,
        playbook_version_id TEXT NOT NULL,
        step_id TEXT NOT NULL,
        step_order INTEGER NOT NULL,
        step_name TEXT NOT NULL,
        step_description TEXT NOT NULL,
        mandatory_status TEXT NOT NULL CHECK (mandatory_status IN ('mandatory', 'conditional', 'optional')),
        expected_predecessor TEXT,
        expected_successor TEXT,
        permitted_alternative_actions_json TEXT NOT NULL DEFAULT '[]',
        approval_requirements TEXT,
        closure_requirements TEXT,
        applicable_evidence_requirements_json TEXT NOT NULL DEFAULT '[]',
        UNIQUE(playbook_version_id, step_id),
        FOREIGN KEY (playbook_version_id) REFERENCES playbook_versions(playbook_version_id) ON DELETE RESTRICT
    );
    """,
    # 11. cases (Central investigation case container pinned to a specific playbook version)
    """
    CREATE TABLE IF NOT EXISTS cases (
        case_id TEXT PRIMARY KEY,
        incident_category TEXT NOT NULL CHECK (incident_category IN ('phishing', 'password_spraying', 'suspicious_powershell', 'persistence_antiforensics')),
        case_status TEXT NOT NULL CHECK (case_status IN ('open', 'in_triage', 'escalated', 'contained', 'closed_true_positive', 'closed_false_positive', 'closed_benign')),
        playbook_id TEXT,
        playbook_version TEXT,
        dataset_source_id TEXT,
        data_quality_status TEXT NOT NULL DEFAULT 'Valid' CHECK (data_quality_status IN ('Valid', 'Valid with warnings', 'Requires review', 'Rejected')),
        summary TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (playbook_id) REFERENCES playbooks(playbook_id),
        FOREIGN KEY (dataset_source_id) REFERENCES datasets(dataset_id)
    );
    """,
    # 12. normalized_events (Normalized security telemetry, phishing, password-spray & PowerShell events)
    """
    CREATE TABLE IF NOT EXISTS normalized_events (
        event_record_id TEXT PRIMARY KEY,
        dataset_id TEXT NOT NULL,
        raw_record_id TEXT NOT NULL,
        schema_type TEXT NOT NULL CHECK (schema_type IN ('security_telemetry', 'phishing', 'password_spray', 'powershell')),
        case_id TEXT,
        event_id TEXT,
        original_timestamp TEXT,
        original_timezone TEXT,
        normalized_utc_timestamp TEXT,
        timestamp_parsing_status TEXT NOT NULL CHECK (timestamp_parsing_status IN ('VALID_UTC', 'CONVERTED_TO_UTC', 'AMBIGUOUS_TIMEZONE_FLAGGED', 'INVALID_TIMESTAMP', 'MISSING_TIMESTAMP')),
        host TEXT,
        source_ip TEXT,
        destination_ip TEXT,
        username TEXT,
        event_type TEXT,
        EventCategory TEXT NOT NULL DEFAULT 'security_telemetry',
        normalized_fields_json TEXT NOT NULL,
        original_fields_json TEXT NOT NULL,
        normalization_version TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (dataset_id) REFERENCES datasets(dataset_id) ON DELETE CASCADE,
        FOREIGN KEY (raw_record_id) REFERENCES raw_records(raw_record_id) ON DELETE CASCADE
    );
    """,
    # 13. analyst_activities (Normalized SOC analyst triage actions — strictly distinct from raw security telemetry)
    """
    CREATE TABLE IF NOT EXISTS analyst_activities (
        activity_record_id TEXT PRIMARY KEY,
        dataset_id TEXT NOT NULL,
        raw_record_id TEXT NOT NULL,
        case_id TEXT NOT NULL,
        activity TEXT NOT NULL,
        original_timestamp TEXT,
        original_timezone TEXT,
        normalized_utc_timestamp TEXT,
        timestamp_parsing_status TEXT NOT NULL,
        incident_type TEXT,
        analyst_id TEXT,
        analyst_role TEXT,
        playbook_id TEXT,
        playbook_version TEXT,
        playbook_step_id TEXT,
        activity_status TEXT,
        outcome TEXT,
        source_system TEXT,
        evidence_reference TEXT,
        timeline_category TEXT NOT NULL DEFAULT 'analyst_activity' CHECK (timeline_category IN (
            'analyst_activity',
            'case_status_transition',
            'evidence_addition',
            'escalation_event'
        )),
        original_fields_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (dataset_id) REFERENCES datasets(dataset_id) ON DELETE CASCADE,
        FOREIGN KEY (raw_record_id) REFERENCES raw_records(raw_record_id) ON DELETE CASCADE
    );
    """,
    # 14. case_event_associations (Explicit identifier & rule-based case associations with manual override audit)
    """
    CREATE TABLE IF NOT EXISTS case_event_associations (
        association_id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        record_type TEXT NOT NULL CHECK (record_type IN ('normalized_event', 'analyst_activity', 'evidence_reference')),
        record_id TEXT NOT NULL,
        association_method TEXT NOT NULL CHECK (association_method IN ('explicit_case_id', 'correlation_rule_match', 'manual_researcher_assignment')),
        matching_rule_description TEXT NOT NULL,
        associated_by TEXT NOT NULL DEFAULT 'system_ingestion',
        associated_at TEXT NOT NULL,
        FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
    );
    """,
    # 15. evidence_references (Cryptographically anchored investigation artefacts linked to cases)
    """
    CREATE TABLE IF NOT EXISTS evidence_references (
        evidence_id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        evidence_type TEXT NOT NULL,
        title TEXT NOT NULL,
        source_record_id TEXT,
        sha256_hash TEXT,
        collected_by TEXT,
        collected_at TEXT NOT NULL,
        notes TEXT,
        FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
    );
    """,
    # 16. ground_truth_labels (Strictly isolated benchmark labels; never exposed to PM4Py or AI inputs)
    """
    CREATE TABLE IF NOT EXISTS ground_truth_labels (
        label_id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL UNIQUE,
        benchmark_stratum TEXT NOT NULL CHECK (benchmark_stratum IN ('phishing', 'password_spraying', 'suspicious_powershell', 'persistence_antiforensics')),
        conformance_class TEXT NOT NULL CHECK (conformance_class IN ('conformant', 'deviating')),
        deviation_type TEXT NOT NULL CHECK (deviation_type IN (
            'none',
            'single_skipped_step',
            'multiple_deviations',
            'reordered_steps',
            'legitimate_conditional_branch',
            'alternative_defensible_action',
            'incomplete_documentation_gap',
            'ambiguous_observability_record'
        )),
        is_justified_deviation INTEGER NOT NULL DEFAULT 0,
        ground_truth_rationale TEXT NOT NULL,
        annotated_by TEXT NOT NULL,
        annotated_at TEXT NOT NULL,
        FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
    );
    """,
    # 17. validation_results (Data quality & research readiness evaluation reports)
    """
    CREATE TABLE IF NOT EXISTS validation_results (
        validation_id TEXT PRIMARY KEY,
        dataset_id TEXT NOT NULL,
        readiness_status TEXT NOT NULL CHECK (readiness_status IN ('Valid', 'Valid with warnings', 'Requires review', 'Rejected')),
        missing_mandatory_fields_count INTEGER NOT NULL DEFAULT 0,
        invalid_timestamps_count INTEGER NOT NULL DEFAULT 0,
        duplicate_records_count INTEGER NOT NULL DEFAULT 0,
        unmapped_activities_count INTEGER NOT NULL DEFAULT 0,
        unassociated_records_count INTEGER NOT NULL DEFAULT 0,
        missing_evidence_refs_count INTEGER NOT NULL DEFAULT 0,
        inconsistent_classifications_count INTEGER NOT NULL DEFAULT 0,
        invalid_case_ids_count INTEGER NOT NULL DEFAULT 0,
        unsupported_mappings_count INTEGER NOT NULL DEFAULT 0,
        checklist_json TEXT NOT NULL,
        evaluated_at TEXT NOT NULL,
        FOREIGN KEY (dataset_id) REFERENCES datasets(dataset_id) ON DELETE CASCADE
    );
    """,
    # 18. processing_runs (Reproducible pipeline execution tracking)
    """
    CREATE TABLE IF NOT EXISTS processing_runs (
        run_id TEXT PRIMARY KEY,
        dataset_id TEXT NOT NULL,
        pipeline_stage TEXT NOT NULL CHECK (pipeline_stage IN ('ingestion', 'normalization', 'provenance_check', 'validation', 'case_association')),
        mapping_id TEXT,
        parameters_json TEXT NOT NULL,
        status TEXT NOT NULL,
        executed_at TEXT NOT NULL,
        FOREIGN KEY (dataset_id) REFERENCES datasets(dataset_id) ON DELETE CASCADE
    );
    """,
    # 19. audit_records (Immutable system-wide audit trail for data governance)
    """
    CREATE TABLE IF NOT EXISTS audit_records (
        audit_id TEXT PRIMARY KEY,
        actor TEXT NOT NULL,
        action_type TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        entity_id TEXT NOT NULL,
        details_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """,
    # =========================================================================
    # FUTURE RESEARCH MODULE TABLES (Prepared for Phase 6 PM4Py & Explainable AI)
    # =========================================================================
    # 20. conformance_results (PM4Py trace replay & alignment metrics)
    """
    CREATE TABLE IF NOT EXISTS conformance_results (
        conformance_id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        playbook_version_id TEXT NOT NULL,
        algorithm TEXT NOT NULL,
        fitness REAL,
        precision_score REAL,
        trace_variant_id TEXT,
        is_premature_termination INTEGER NOT NULL DEFAULT 0,
        computed_at TEXT NOT NULL,
        FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE,
        FOREIGN KEY (playbook_version_id) REFERENCES playbook_versions(playbook_version_id)
    );
    """,
    # 21. deviation_findings (Granular skipped, reordered, repeated, or additional activities)
    """
    CREATE TABLE IF NOT EXISTS deviation_findings (
        deviation_id TEXT PRIMARY KEY,
        conformance_id TEXT NOT NULL,
        case_id TEXT NOT NULL,
        deviation_category TEXT NOT NULL CHECK (deviation_category IN ('skipped_activity', 'reordered_activity', 'repeated_activity', 'additional_activity', 'premature_termination')),
        playbook_step_id TEXT,
        observed_activity_record_id TEXT,
        description TEXT NOT NULL,
        FOREIGN KEY (conformance_id) REFERENCES conformance_results(conformance_id) ON DELETE CASCADE
    );
    """,
    # 22. ai_model_registry (Configurable hosted or local LLM providers)
    """
    CREATE TABLE IF NOT EXISTS ai_model_registry (
        model_id TEXT PRIMARY KEY,
        provider_name TEXT NOT NULL,
        model_name TEXT NOT NULL,
        model_version TEXT NOT NULL,
        endpoint_url TEXT,
        is_local INTEGER NOT NULL DEFAULT 0,
        is_enabled INTEGER NOT NULL DEFAULT 0,
        registered_at TEXT NOT NULL
    );
    """,
    # 23. prompt_versions (Version-controlled prompts for reproducible XAI evaluation)
    """
    CREATE TABLE IF NOT EXISTS prompt_versions (
        prompt_version_id TEXT PRIMARY KEY,
        prompt_name TEXT NOT NULL,
        version_tag TEXT NOT NULL UNIQUE,
        system_template TEXT NOT NULL,
        output_json_schema TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """,
    # 24. ai_assessments (Evidence-grounded XAI findings requiring human validation)
    """
    CREATE TABLE IF NOT EXISTS ai_assessments (
        finding_id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        finding_category TEXT NOT NULL CHECK (finding_category IN (
            'investigation_completeness',
            'evidence_sufficiency',
            'decision_justification',
            'escalation_quality',
            'documentation_quality',
            'closure_quality'
        )),
        severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
        explanation TEXT NOT NULL,
        supporting_evidence_refs_json TEXT NOT NULL,
        related_playbook_step TEXT,
        calibrated_confidence REAL,
        provider_info TEXT NOT NULL,
        model_version TEXT NOT NULL,
        prompt_version TEXT NOT NULL,
        assessment_timestamp TEXT NOT NULL,
        human_review_status TEXT NOT NULL DEFAULT 'PENDING_HUMAN_REVIEW' CHECK (human_review_status IN ('PENDING_HUMAN_REVIEW', 'VALIDATED_ACCURATE', 'REJECTED_UNSUPPORTED', 'MODIFIED_BY_AUDITOR')),
        FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
    );
    """,
    # 25. human_review_records (Researcher validation of AI recommendations)
    """
    CREATE TABLE IF NOT EXISTS human_review_records (
        review_id TEXT PRIMARY KEY,
        finding_id TEXT NOT NULL,
        reviewer_id TEXT NOT NULL,
        decision TEXT NOT NULL,
        reviewer_notes TEXT NOT NULL,
        reviewed_at TEXT NOT NULL,
        FOREIGN KEY (finding_id) REFERENCES ai_assessments(finding_id) ON DELETE CASCADE
    );
    """,
    # 26. research_experiments (Experimental run configurations over the 75-case benchmark)
    """
    CREATE TABLE IF NOT EXISTS research_experiments (
        experiment_id TEXT PRIMARY KEY,
        experiment_name TEXT NOT NULL,
        benchmark_version TEXT NOT NULL,
        process_mining_config_json TEXT NOT NULL,
        ai_config_json TEXT NOT NULL,
        executed_at TEXT NOT NULL
    );
    """,
    # 27. evaluation_metrics (Empirical metrics comparing automated findings vs isolated ground truth)
    """
    CREATE TABLE IF NOT EXISTS evaluation_metrics (
        metric_id TEXT PRIMARY KEY,
        experiment_id TEXT NOT NULL,
        stratum TEXT NOT NULL,
        metric_name TEXT NOT NULL,
        metric_value REAL NOT NULL,
        computed_at TEXT NOT NULL,
        FOREIGN KEY (experiment_id) REFERENCES research_experiments(experiment_id) ON DELETE CASCADE
    );
    """
]

INDEX_DDL = [
    "CREATE INDEX IF NOT EXISTS idx_raw_records_dataset ON raw_records(dataset_id);",
    "CREATE INDEX IF NOT EXISTS idx_norm_events_case ON normalized_events(case_id);",
    "CREATE INDEX IF NOT EXISTS idx_norm_events_ts ON normalized_events(normalized_utc_timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_analyst_act_case ON analyst_activities(case_id);",
    "CREATE INDEX IF NOT EXISTS idx_analyst_act_ts ON analyst_activities(normalized_utc_timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_case_assoc_case ON case_event_associations(case_id);",
    "CREATE INDEX IF NOT EXISTS idx_playbook_steps_ver ON playbook_steps(playbook_version_id);",
]
