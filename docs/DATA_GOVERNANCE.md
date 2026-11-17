# SOC-QA Intelligence — Security, Provenance & Data Governance

## 1. Artefact Safety & Non-Execution Policy
- Uploaded files are restricted to `.csv`, `.json`, `.jsonl`, `.ndjson`, and `.xes` with strict upload size enforcement (`MAX_UPLOAD_SIZE_BYTES`) and filename sanitization (`sanitize_filename`) to prevent path traversal (`../`).
- Uploaded attachments, PowerShell script blocks, or binaries are never executed.
- Untrusted HTML in phishing email bodies is never rendered directly (`<` and `>` are neutralized), and untrusted log/email text is scrubbed for prompt-injection directives (`sanitize_untrusted_text_for_ai`) before any future AI context packaging.

## 2. Immutable Provenance & Cryptographic Integrity
- Every ingested file is preserved unchanged under `data/raw/{dataset_id}_{filename}` and hashed via `hashlib.sha256`.
- Normalization writes separate records to `normalized_events` / `analyst_activities` and `data/normalized/{dataset_id}_normalized.json`, leaving the raw source untouched.
- Any modification to an on-disk raw file is immediately flagged as `INTEGRITY_MISMATCH` by `/api/v1/provenance/{dataset_id}/verify`.
