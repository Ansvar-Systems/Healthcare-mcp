# Healthcare Intelligence MCP

Healthcare Intelligence MCP is a domain-intelligence layer for healthcare threat modeling.

It is intentionally **not** a duplicate legal text repository. It classifies healthcare context and routes obligations to existing authoritative MCPs:
- EU Regulations MCP
- US Regulations MCP
- Security Controls MCP
- Law MCPs for state/member-state overlays

## Scope

This MCP focuses on:
- Healthcare data classification taxonomy (ePHI, Part 2, genetic, and operational categories)
- Healthcare architecture patterns (EHR/FHIR, DICOM/PACS, IoMT contexts)
- Healthcare threat scenarios (clinical + cyber impact)
- Enriched threat expert profiles (MITRE techniques, exploit preconditions, detection indicators, likelihood drivers, historical incident patterns)
- Technical standards mapping (FHIR, DICOM, IEC 62304, ISO 14971, IEC 80001-1, FDA guidance)
- Applicability and breach-routing logic for EU/US
- Conflict-aware obligation resolution (`strictest_wins`) for overlapping multi-jurisdiction requirements
- Contract-chain intelligence (BAA, DPA, SCC-style transfer mechanisms, Part 2 redisclosure, EHDS secondary-use permit signals)
- Evidence template planning for major healthcare audit types

Current jurisdiction overlay packs:
- `SE` (Sweden): GDPR Art. 9, NIS2, Patientdatalagen routing
- `US-CA` (California): HIPAA, CMIA, CCPA/CPRA, California telehealth law, FDA SaMD/AI considerations
- `DE` (Germany): MDR, GDPR, BDSG, AI Act, NIS2 routing
- `US-TX` (Texas): HIPAA + Texas healthcare privacy overlays
- `NL` (Netherlands): GDPR, NIS2, and Dutch healthcare confidentiality overlays

For countries/states without an explicit overlay pack, the applicability engine synthesizes a jurisdiction-family baseline:
- EU member states: GDPR Art. 9 + NIS2 + member-state law route (+ MDR/AI Act when relevant)
- US states/DC: HIPAA + state law route (+ FDA 524B when device/clinical AI context is present)

## Tool Set

- `about`
- `list_sources`
- `list_architecture_patterns`
- `list_profiles`
- `classify_data` (universal alias)
- `classify_health_data`
- `classify_medical_device`
- `get_architecture_pattern`
- `get_domain_threats` (universal alias)
- `get_healthcare_threats`
- `get_threat_response_playbook`
- `assess_applicability` (universal alias)
- `assess_healthcare_applicability`
- `map_to_technical_standards` (universal alias)
- `map_to_healthcare_standards`
- `search_domain_knowledge`
- `assess_breach_obligations`
- `build_control_baseline` (universal alias)
- `build_healthcare_baseline`
- `build_evidence_plan`
- `create_remediation_backlog`
- `compare_jurisdictions`
- `resolve_authoritative_context`
- `get_protocol_security`
- `assess_clinical_risk`
- `map_hipaa_safeguards`

## Architecture

1. Agent provides organization and system context.
2. Healthcare MCP classifies data, architecture, and threat relevance.
3. Healthcare MCP returns routed references for regulation/control MCP calls.
4. Agent composes final outputs from authoritative text + healthcare context.

## Local Development

```bash
npm install
npm run build:db
npm run build
npm test
npm run test:benchmark
npm run drift:hashes
npm run drift:verify
npm run check:source-updates
```

Run stdio server:

```bash
npx tsx src/index.ts
```

Run HTTP server:

```bash
PORT=3000 npx tsx src/http-server.ts
```

Health endpoint:

```bash
curl -s http://localhost:3000/health
```

Returns `ok`, `stale`, or `degraded` with freshness metadata.

Configure live upstream routing (optional):

```bash
export HEALTHCARE_UPSTREAM_EU_REGS_URL="https://eu-regulations-mcp.vercel.app/mcp"
export HEALTHCARE_UPSTREAM_US_REGS_URL="https://us-regulations-mcp.vercel.app/mcp"
export HEALTHCARE_UPSTREAM_SECURITY_CONTROLS_URL="https://security-controls-mcp.vercel.app/mcp"
export HEALTHCARE_UPSTREAM_US_LAW_URL="https://us-law-mcp.vercel.app/mcp"
export HEALTHCARE_UPSTREAM_EU_LAW_URL="https://<member-state-law-router>/mcp"
```

Use live upstream composition via:
- `resolve_authoritative_context`
- `compare_jurisdictions` with `resolve_authoritative=true`

Run live authoritative regression harness (optional):

```bash
npm run test:live
npm run test:live:strict
```

Requires one or more configured upstream endpoint environment variables.
- `test:live` enforces configurable success ratio (`LIVE_REQUIRED_MIN_OK_RATIO`, default `0.8`).
- `test:live:strict` requires all configured upstreams to succeed.

## Data and Provenance

- Schema: `data/schema.sql`
- Seed data: `data/seed/*.json`
- Provenance file: `sources.yml`

## Production Hardening Checklist

- Golden accuracy and sampling tests for architecture/data/threat/applicability domains
- Full EU member-state and US state/DC applicability completeness tests
- Malformed-input robustness tests for actionable error handling
- Expert benchmark grade gate (`fixtures/expert-benchmark.json`)
- Transport parity test (`registry` manifest vs live `/mcp` tools list)
- Drift hash generation and verification in CI
- 6-layer security scan workflow in GitHub Actions
- Source freshness check workflow
- Scheduled live upstream authoritative regression workflow
- Dual transport support (`stdio` and streamable HTTP `/mcp`)

## Current Status

Repository is production-ready as a domain-router MCP with healthcare ontology coverage and US/EU routing composition. Continue improving by adding deeper per-country/state overlay packs and expanding live authoritative endpoint integration tests.

Latest expertise upgrades in this branch:
- Advanced `classify_medical_device` outputs with structured FDA class, MDR class, IMDRF SaMD category, and AI Act high-risk signals.
- Breach engine now supports exact-jurisdiction + family fallback matching (`US-CA` + `US`, `SE` + `EU`) with `decision_tree` and `notification_matrix`.
- Applicability now includes explicit `contracting_obligations` for BAA/DPA/SCC/Part 2/EHDS chain logic.
- Evidence templates expanded to `MDR_IVDR`, `ISO27001_ISO27799`, `HITRUST`, `AI_ACT`, and `DCB0129_DCB0160`.
- Protocol security expanded with IHE profile-level guidance (`ATNA`, `XUA`, `IUA`, `SeR`).
- Added a threat response playbook layer (containment, clinical safety, forensic artifacts, recovery validation, communication, escalation routes).
