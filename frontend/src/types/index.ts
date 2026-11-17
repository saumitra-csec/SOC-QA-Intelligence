export type DatasetCategory =
  | 'phishing_telemetry'
  | 'password_spray_telemetry'
  | 'suspicious_powershell_telemetry'
  | 'analyst_activity_logs'
  | 'case_metadata'
  | 'reference_playbooks'
  | 'evidence_metadata'
  | 'ground_truth_annotations';

export type ReadinessStatus = 'Valid' | 'Valid with warnings' | 'Requires review' | 'Rejected';

export interface ProvenanceManifestRecord {
  dataset_id: string;
  original_filename: string;
  original_source_url: string;
  source_organization: string;
  dataset_version: string;
  acquisition_date: string;
  upload_date: string;
  file_format: string;
  file_size_bytes: number;
  license_information: string;
  sha256_checksum: string;
  processing_status: string;
  normalization_version: string;
  associated_case_ids: string[];
  integrity_status: string;
  last_verified_at: string;
}

export interface CaseOverview {
  case_id: string;
  incident_category: 'phishing' | 'password_spraying' | 'suspicious_powershell';
  case_status: string;
  playbook_id?: string;
  playbook_version?: string;
  applicable_playbook_display: string;
  dataset_source_id?: string;
  data_quality_status: ReadinessStatus;
  telemetry_event_count: number;
  analyst_activity_count: number;
  evidence_count: number;
  summary: string;
}

export interface TimelineItem {
  timeline_id: string;
  raw_record_id: string;
  dataset_id?: string;
  timestamp_utc: string;
  original_timestamp: string;
  event_class:
    | 'security_telemetry'
    | 'analyst_activity'
    | 'case_status_transition'
    | 'evidence_addition'
    | 'escalation_event';
  is_analyst_action: boolean;
  title: string;
  actor_or_host: string;
  playbook_step_id?: string;
  outcome?: string;
  evidence_reference?: string;
  details: Record<string, unknown>;
}
