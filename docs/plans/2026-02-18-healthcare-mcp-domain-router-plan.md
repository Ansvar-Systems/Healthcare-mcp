# Healthcare MCP Domain-Router Plan

## Goal

Build Healthcare MCP as the domain-intelligence layer for healthcare threat modeling, while delegating authoritative legal/control text retrieval to existing regulation and control MCPs.

## Design Principles

- Do not duplicate legal source corpora already managed by regulation/law MCPs.
- Keep healthcare ontology and routing logic in one place.
- Output must be machine-usable and composable (stable IDs, references, deadlines, routes).
- Include healthcare operational impact context (clinical safety, continuity, patient diversion).

## Domain Models

- Health data categories
- Medical device classification heuristics
- Architecture patterns (components, trust boundaries, data flows, weak points)
- Threat scenarios (clinical impact + MITRE tactics)
- Technical standards and mappings
- Breach timeline rules
- Evidence template catalog

## Tool Contract

- about
- list_profiles
- classify_health_data
- classify_medical_device
- get_architecture_pattern
- get_healthcare_threats
- assess_healthcare_applicability
- map_to_healthcare_standards
- assess_breach_obligations
- build_healthcare_baseline
- build_evidence_plan
- compare_jurisdictions

## Composition with Existing MCPs

- EU_Regulations_MCP: GDPR, NIS2, MDR/IVDR, AI Act, EHDS
- US_Regulations_MCP: HIPAA, HITECH, FTC health breach, FDA route references
- Security_Controls_MCP: authoritative control text and cross-framework mappings
- Law MCPs: state/member-state overlays

Healthcare MCP synthesizes domain context and orchestrates calls but does not replace authoritative text MCPs.

## Next Build Steps

1. Expand deterministic crosswalk IDs for regulation/control/standard joins.
2. Extend live upstream orchestration coverage beyond search to citation and provision retrieval.
3. Add integration tests against real deployed MCP endpoints in a controlled CI environment.
4. Expand architecture patterns and threat scenarios to cover telehealth, HIE, LIS/RIS, and IoMT fleet operations.
5. Add state/member-state specialization packs (US state overlays and EU member-state overlays).

## Implemented in This Scaffold Iteration

- Added live Streamable HTTP MCP upstream client.
- Added `resolve_authoritative_context` tool for runtime composition with EU/US regulation, controls, and law MCP endpoints.
- Added optional authoritative resolution path in `compare_jurisdictions`.
- Added universal spec-alignment tool names (`list_sources`, `list_architecture_patterns`, `classify_data`, `get_domain_threats`, `assess_applicability`, `map_to_technical_standards`, `search_domain_knowledge`, `build_control_baseline`, `create_remediation_backlog`).
- Added healthcare-specific tools from the domain spec (`get_protocol_security`, `assess_clinical_risk`, `map_hipaa_safeguards`).
- Added jurisdiction overlay pack with applicability routing for `SE`, `US-CA`, and `DE`, including scenario-specific obligation mapping.
- Added EU/US-wide synthesized fallback applicability so all EU member states and US states/DC return baseline healthcare obligation routing even without explicit overlay packs.
- Added conflict-aware applicability resolver (`strictest_wins`) that deterministically selects stricter obligations in overlapping cross-jurisdiction cases.
- Added applicability sampling tests for `SE` EHR, `US-CA` telehealth AI, and `DE` medical-device AI scenarios.
- Added phase-2 sampling suite (architecture/data/threat/applicability/comparison/negative/edge tests).
- Added optional live-authoritative regression harness (`LIVE_UPSTREAM_TESTS=1`) for real upstream MCP endpoint validation.
- Added strict live regression mode and configurable upstream success-ratio threshold (`LIVE_STRICT`, `LIVE_REQUIRED_MIN_OK_RATIO`).
- Added scheduled GitHub Actions live upstream regression workflow with secret-backed endpoint configuration.
- Added expert benchmark grade-gate suite from weighted scenarios (`fixtures/expert-benchmark.json`).
- Added transport parity integration test to verify local `/mcp` tool manifest matches registry tool definitions.
- Added jurisdiction completeness tests covering all EU member states and all US states/DC.
- Added malformed-input robustness tests for actionable error behavior.
- Added drift hash generation + verification scripts and CI verification gate.
- Added CI, source-check, and security scan workflow scaffolding.
- Expanded medical-device classification to output FDA class, MDR class, IMDRF SaMD category, and AI Act high-risk signals.
- Expanded breach obligation engine with exact-jurisdiction + family fallback matching, decision-tree output, and per-jurisdiction notification matrix.
- Added explicit contracting-obligation outputs to applicability (`BAA`, `DPA`, `SCC_OR_EQUIVALENT_TRANSFER_MECHANISM`, Part 2 redisclosure, EHDS secondary-use permit).
- Expanded evidence template coverage to include `MDR_IVDR`, `ISO27001_ISO27799`, `HITRUST`, `AI_ACT`, and `DCB0129_DCB0160`.
- Expanded protocol security coverage to include IHE profile-level guidance (`ATNA`, `XUA`, `IUA`, `SeR`).
- Added queryable threat expert profiles with ATT&CK technique mappings, exploit preconditions, likelihood factors, detection indicators, and historical incident cues.
- Added threat response playbook knowledge with containment, clinical-safety, forensic, recovery-validation, communication, and escalation-route actions per threat.
