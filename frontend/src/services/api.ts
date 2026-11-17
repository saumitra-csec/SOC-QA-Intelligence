const API_BASE = import.meta.env.VITE_API_BASE_URL || '/api/v1';

export async function fetchOverviewMetrics() {
  const res = await fetch(`${API_BASE}/dashboard/overview`);
  if (!res.ok) throw new Error(`Overview fetch failed: ${res.statusText}`);
  return res.json();
}

export async function uploadDatasetFile(formData: FormData) {
  const res = await fetch(`${API_BASE}/ingestion/upload`, {
    method: 'POST',
    body: formData,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Upload failed');
  }
  return res.json();
}

export async function verifyDatasetIntegrity(datasetId: string) {
  const res = await fetch(`${API_BASE}/provenance/${datasetId}/verify`, {
    method: 'POST',
  });
  if (!res.ok) throw new Error('Integrity verification failed');
  return res.json();
}

export async function runNormalization(payload: {
  dataset_id: string;
  target_schema_type: string;
  field_mapping: Record<string, string>;
  normalization_version?: string;
}) {
  const res = await fetch(`${API_BASE}/normalization/run`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error('Normalization failed');
  return res.json();
}

export async function fetchCaseTimeline(caseId: string, category = 'all') {
  const params = new URLSearchParams();
  if (category && category !== 'all') params.set('category', category);
  const res = await fetch(`${API_BASE}/cases/${caseId}/timeline?${params.toString()}`);
  if (!res.ok) throw new Error('Timeline fetch failed');
  return res.json();
}
