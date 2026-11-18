# Gemini task: integrate institutional playbooks into SOC-QA Intelligence

You are modifying the existing SOC-QA Intelligence repository. First inspect its current database models, playbook ingestion pipeline, process-mining contracts, conformance evaluator, API routes, tests, and frontend before proposing changes.

Use this pack as a reference corpus and ingestion specification.

## Non-negotiable constraints

1. Preserve original source files byte-for-byte. Do not overwrite, transform, or discard them.
2. Treat `metadata/institutional-playbook.schema.json` as the target normalised representation, but adapt it to the existing project architecture rather than introducing a parallel incompatible schema.
3. Treat each JSON file in `normalized/` as a working extraction, not authoritative ground truth. Preserve its `normalization.status`.
4. Do not mark a playbook `validated` until a human has reviewed every action, branch, mandatory/conditional designation, evidence requirement, and source anchor.
5. Never invent missing source steps. Where content is unavailable, mark the extraction incomplete and record the exact missing source material.
6. Preserve institution, version, jurisdiction, scope, source URL, page/section anchors, retrieval date, licence/reuse note, and SHA-256 of original files.
7. Distinguish operational SOC playbooks from national/sector coordination playbooks and from standards/frameworks.
8. Do not merge CISA, Microsoft, Scottish Government, AWS, Splunk, NOCS, or other institution-specific procedures into one generic playbook.
9. Do not assume a conditional action is mandatory for every incident.
10. Add tests for schema validation, source provenance, branch integrity, duplicate IDs, versioning, and prevention of unreviewed playbooks entering conformance evaluation.

## Required workflow

A. Inspect the existing repository and provide a short architecture impact assessment before editing.
B. Map the schema fields to existing database entities. Reuse existing tables where suitable; propose migrations only where needed.
C. Implement source registry and version-aware playbook ingestion.
D. Implement JSON Schema validation and a human-review status gate.
E. Implement source anchors and provenance retention.
F. Add import support for DOCX, PDF, HTML, Markdown, YAML, and JSON only where reliable extraction is possible. Preserve raw originals.
G. Keep extraction, normalisation, human validation, and conformance evaluation as separate stages.
H. Add tests and update docs.

## Evaluation semantics

The evaluator must distinguish:
- performed
- not_performed
- not_documented
- not_applicable
- out_of_order
- evidence_insufficient
- condition_not_met

A missing evidence artefact must not automatically be treated as proof that an action was not performed. Conditional steps must be evaluated against their triggering condition. A source playbook's optional or illustrative action must not become mandatory by default.

## Deliverables

- Architecture impact report
- Database migration (if required)
- Source registry and ingestion code
- Schema validation
- Human review workflow
- Unit/integration tests
- Documentation describing provenance, licensing, and limitations
- A report listing which sources are fully ingested, partially ingested, or awaiting original-file retrieval

Do not touch the separate DFIR Timeline Analyzer project. SOC-QA Intelligence is the target repository.
