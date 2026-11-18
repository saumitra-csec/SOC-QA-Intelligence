# SOC-QA Intelligence — Institutional Playbook Integration Pack

Pack created: 2026-11-18

## Important status notice

This is an **integration starter pack**, not a ZIP of all original source documents.
The public sources were verified through their official pages, and selected publicly visible text was normalised into JSON. Binary download of DOCX/PDF/repository files was unavailable in the execution environment. No missing original has been fabricated.

Check `metadata/source_manifest.csv` for source URLs, format, reuse notes, and retrieval/normalisation status.

## Contents

- `normalized/`: three machine-readable working examples:
  - Microsoft phishing investigation workflow
  - Australian NOCS Financial Sector Playbook
  - CISA incident-response high-level workflow
- `metadata/institutional-playbook.schema.json`: JSON Schema for the normalised action representation.
- `metadata/source_manifest.json` and `.csv`: source register for official and vendor materials.
- `GEMINI_INTEGRATION_PROMPT.md`: instructions for Gemini to ingest the corpus safely.
- `originals/PLACEHOLDER_README/`: explains how to add originals after downloading them from their official sources.

## Recommended ingestion sequence

1. Fetch each source from its official URL.
2. Store the untouched original under `originals/<institution>/`.
3. Calculate SHA-256 over the original bytes and record it in the source record.
4. Extract candidate actions and source anchors (page, heading, paragraph).
5. Normalise into the schema.
6. Have a human reviewer approve mandatory/conditional status, branches, evidence requirements, and ordering.
7. Only then mark a playbook `human_reviewed` or `validated` and make it available to the conformance engine.

## Research integrity rules

- Never equate a missing log/evidence reference with proof that an action was not performed.
- Distinguish `not_performed`, `not_documented`, `not_applicable`, `out_of_order`, and `evidence_insufficient`.
- Preserve institution-specific variants. Do not merge different institutions into one universal workflow.
- Treat government sector coordination playbooks (e.g. NOCS) separately from technical SOC analyst procedures.
- Treat NIST/FIRST/NCSC frameworks as reference material unless they contain an explicitly operational sequence.
- Do not infer mandatory actions from examples or optional recommendations.
- Record source version, publication date, retrieval date, licence, and exact source anchor.
- Keep original wording and normalised wording in separate fields.
