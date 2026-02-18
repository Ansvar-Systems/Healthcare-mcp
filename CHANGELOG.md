# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]
- Added tag-driven npm publish workflow with provenance attestation (`.github/workflows/publish.yml`).
- Aligned MCP registry identity metadata (`mcpName` and `server.json.name` now both `eu.ansvar/healthcare-intelligence`).
- Expanded tool input schemas with complete parameter-level descriptions/defaults to improve agent self-selection and argument construction reliability.
- Updated FDA cybersecurity standard metadata to current guidance versioning and added explicit `FDA_524B` requirement mapping in standards crosswalk output.
- Added regression coverage to ensure `FDA_524B` continuously resolves to mapped FDA cybersecurity guidance metadata.
- Expanded `classify_medical_device` with structured FDA/MDR class outputs, IMDRF SaMD category signals, and AI Act high-risk indicators.
- Expanded breach logic with exact-jurisdiction + family fallback matching, decision-tree output, and per-jurisdiction notification matrix.
- Added explicit contract-chain applicability output for `BAA`, `DPA`, `SCC_OR_EQUIVALENT_TRANSFER_MECHANISM`, Part 2 redisclosure chain, and EHDS secondary-use permits.
- Expanded evidence templates to cover `MDR_IVDR`, `ISO27001_ISO27799`, `HITRUST`, `AI_ACT`, and `DCB0129_DCB0160`.
- Expanded protocol security coverage with profile-level IHE responses (`ATNA`, `XUA`, `IUA`, `SeR`).
- Added threat expert profile dataset and output enrichment for ATT&CK techniques, exploit preconditions, likelihood factors, detection indicators, and historical incident patterns.
- Added per-threat response playbook dataset and tool output (`get_threat_response_playbook`) with triage priority, containment, clinical safety, forensic, recovery, communication, and escalation routing guidance.
- Added advanced expertise regression tests and updated benchmark/golden fixtures for stricter authoritative-validation behavior in cross-border overlap scenarios.

## [0.1.0] - 2026-02-18
- Initial scaffold for Healthcare MCP domain-intelligence layer.
- Added healthcare threat modeling tool contracts and stubs.
- Added SQLite schema, seed data, and DB build script.
