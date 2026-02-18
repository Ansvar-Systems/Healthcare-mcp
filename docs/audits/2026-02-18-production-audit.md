# Healthcare MCP Production Audit

- **Audit date:** 2026-02-18
- **Audited repo:** `Healthcare-mcp`
- **Audited standard:** `mcp-production-audit.md` v1.0 (2026-02-17)
- **Auditor mode:** Code + test + provenance + sampling

## 0) Server Profile (Unlisted Template)

| Field | Value |
|---|---|
| Server Name | Healthcare Intelligence MCP |
| Repository | https://github.com/Ansvar-Systems/Healthcare-mcp |
| Domain | Healthcare IT/CS threat-modeling domain intelligence + MCP routing |
| Authoritative Sources | HHS OCR, EUR-Lex, FDA, NIST, HL7, DICOM, IHE, MITRE, ENISA (via `sources.yml`) |
| Language | TypeScript |
| Database | SQLite + FTS5 (`data/healthcare.db`) |
| Transport | stdio + Streamable HTTP |
| Deployment | Vercel-style API (`api/mcp.ts`, `api/health.ts`) |
| npm Package | `@ansvar/healthcare-mcp` |
| Endpoint | Not validated live in this environment |
| DB Size | ~287 KB (`npm pack --dry-run`) |
| Known Gotcha | Uses `better-sqlite3` instead of WASM SQLite driver expected by this audit standard |

## 1) Phase-by-Phase Findings

### Phase 1: Structural & Protocol Compliance

- **PASS** MCP JSON-RPC handlers are present via SDK (`initialize`, `tools/list`, `tools/call`) and tool registration is centralized in `/Users/jeffreyvonrotz/Projects/Healthcare-mcp/src/tools/registry.ts:979`.
- **PASS** stdio entrypoint is wired in `bin` and starts correctly (`/Users/jeffreyvonrotz/Projects/Healthcare-mcp/package.json:8`, `/Users/jeffreyvonrotz/Projects/Healthcare-mcp/src/index.ts:1`).
- **PASS** Streamable HTTP transport is implemented for local HTTP and Vercel (`/Users/jeffreyvonrotz/Projects/Healthcare-mcp/src/http-server.ts:91`, `/Users/jeffreyvonrotz/Projects/Healthcare-mcp/api/mcp.ts:43`).
- **PASS** cancellation notification compatibility comes from MCP SDK (`/Users/jeffreyvonrotz/Projects/Healthcare-mcp/node_modules/@modelcontextprotocol/sdk/dist/esm/server/index.js:201`).
- **PASS** tool names satisfy ChatGPT constraints (`26` tools, max length `31`, regex valid).
- **PASS** parameter description coverage was improved to complete (no missing property descriptions in `createToolDefinitions`).
- **WARNING** schema examples are still absent in tool input schemas; this reduces first-try call quality for new agents.
- **WARNING** full live dual-channel verification was partially blocked by sandbox socket restrictions (`EPERM` on local listen). Transport parity is tested, but the test can no-op in socket-restricted environments (`/Users/jeffreyvonrotz/Projects/Healthcare-mcp/tests/transport-parity.test.ts:101`).

### Phase 2: Data Accuracy & Verification

- **PASS** provenance file exists and is comprehensive (`/Users/jeffreyvonrotz/Projects/Healthcare-mcp/sources.yml:1`).
- **PASS** DB metadata includes freshness/version fields (`schema_version`, `tier`, `last_source_check`, `coverage_regions`).
- **PASS** drift and golden checks are present and passing (`21` golden tests, drift hash verification succeeds).
- **PASS** referential integrity and FTS are implemented in schema (`/Users/jeffreyvonrotz/Projects/Healthcare-mcp/data/schema.sql:1`).
- **WARNING** freshness script validates static `data_obtained` dates only; it does not fetch/compare upstream authoritative revisions (`/Users/jeffreyvonrotz/Projects/Healthcare-mcp/scripts/check-source-updates.ts:49`).
- **WARNING** NIS2 24h legal text could not be directly re-opened from EUR-Lex in this environment due access/challenge constraints; rule remains marked inferred in tool output.

### Phase 3: Agent Optimization & Robustness

- **PASS** malformed input handling is well-covered and returns actionable hints (`/Users/jeffreyvonrotz/Projects/Healthcare-mcp/tests/error-handling.test.ts:13`).
- **PASS** query sanitization exists for FTS and free-text search (`/Users/jeffreyvonrotz/Projects/Healthcare-mcp/src/tools/get_healthcare_threats.ts:36`, `/Users/jeffreyvonrotz/Projects/Healthcare-mcp/src/tools/search_domain_knowledge.ts:11`).
- **PASS** SQL is parameterized in tool queries.
- **WARNING** token footprint is high for common calls:
  - `classify_health_data`: ~1.8k tokens
  - `get_healthcare_threats` (limit=5): ~2.9k tokens
  - `assess_healthcare_applicability`: ~3.9k tokens
- **WARNING** `LIKE` queries on architecture/standards search paths can degrade under larger datasets (`/Users/jeffreyvonrotz/Projects/Healthcare-mcp/src/tools/search_domain_knowledge.ts:83`).
- **FAIL (Critical)** SQLite driver is `better-sqlite3` rather than WASM SQLite expected by this audit standard for serverless portability (`/Users/jeffreyvonrotz/Projects/Healthcare-mcp/package.json:64`, `/Users/jeffreyvonrotz/Projects/Healthcare-mcp/src/db.ts:1`).

### Phase 4: Deployment & Operational Readiness

- **PASS** documentation, changelog, and provenance are present (`README.md`, `CHANGELOG.md`, `sources.yml`).
- **PASS** CI is robust and includes build/test/drift/package checks (`/Users/jeffreyvonrotz/Projects/Healthcare-mcp/.github/workflows/ci.yml:1`).
- **PASS** 6-layer security scan workflow is present (CodeQL, Semgrep, Trivy, Gitleaks, Socket, Scorecard) (`/Users/jeffreyvonrotz/Projects/Healthcare-mcp/.github/workflows/security-scans.yml:1`).
- **PASS** publish workflow is tag-triggered and uses npm provenance (`/Users/jeffreyvonrotz/Projects/Healthcare-mcp/.github/workflows/publish.yml:3`, `/Users/jeffreyvonrotz/Projects/Healthcare-mcp/.github/workflows/publish.yml:39`).
- **PASS** `mcpName` and `server.json.name` are aligned (`/Users/jeffreyvonrotz/Projects/Healthcare-mcp/package.json:4`, `/Users/jeffreyvonrotz/Projects/Healthcare-mcp/server.json:1`).
- **WARNING** `npm audit` could not run due network DNS restrictions in this environment, so vulnerability status is not fully verified here.

### Phase 5: Ansvar Integration Readiness

- **PASS** composability is strong: healthcare router tools explicitly route to regulation/control/law MCPs.
- **PASS** coverage tests include jurisdiction completeness and overlap/conflict behavior (`/Users/jeffreyvonrotz/Projects/Healthcare-mcp/tests/jurisdiction-completeness.test.ts:1`, `/Users/jeffreyvonrotz/Projects/Healthcare-mcp/tests/applicability-conflicts.test.ts:1`).
- **WARNING** live upstream authoritative regression depends on configured secrets and was skipped locally when endpoints are absent (`/Users/jeffreyvonrotz/Projects/Healthcare-mcp/tests/live-authoritative-regression.test.ts:1`).

## 2) Phase 2.3 Sampling (Expected vs Actual)

| Sample | Authoritative Reference | Expected | MCP Actual | Result |
|---|---|---|---|---|
| HIPAA breach notification timing | [HHS OCR Breach Notification Rule](https://www.hhs.gov/hipaa/for-professionals/breach-notification/index.html) | Notification without unreasonable delay, no later than 60 days | `rule_us_hipaa_60d.deadline_hours = 1440` (`60` days) | PASS |
| HIPAA breach notice content | [HHS OCR Breach Notification Rule](https://www.hhs.gov/hipaa/for-professionals/breach-notification/index.html) | Description + info types + mitigation + contact info | `content_requirements`: breach description, types of information, mitigation actions, contact method | PASS |
| GDPR Art. 33 timing | [EUR-Lex GDPR (CELEX:32016R0679)](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng) | Notify SA within 72 hours where feasible | `rule_eu_gdpr.deadline_hours = 72` | PASS |
| NIST SP 800-66 revision | [NIST SP 800-66r2](https://csrc.nist.gov/pubs/sp/800/66/r2/final) | Revision 2 | `nist_sp_800_66.version = "Rev.2"` | PASS |
| HL7 FHIR current major release | [HL7 FHIR Release 5](https://www.hl7.org/fhir/R5/) | R5 is current major published release | `hl7_fhir_r5.version = "R5"` and `status = "active"` | PASS |
| DICOM current edition | [DICOM Current Edition](https://www.dicomstandard.org/current/) | Current edition available and maintained | `dicom.version = "current"` and `status = "active"` | PASS |
| FDA device cyber guidance recency | [FDA Cybersecurity in Medical Devices](https://www.fda.gov/medical-devices/digital-health-center-excellence/cybersecurity) | Latest final guidance supersedes older premarket guidance | Updated to `version = "2026"` and added `FDA_524B` mapping | PASS (remediated during audit) |

### Discrepancies Found

- **Resolved during this audit:** FDA guidance entry previously pointed to `2023` without a direct `FDA_524B` standards mapping. Updated in `/Users/jeffreyvonrotz/Projects/Healthcare-mcp/data/seed/technical_standards.json:108` and validated through `map_to_healthcare_standards`.
- **No remaining factual mismatches found in sampled points above.**

## 3) Scores

| Category | Score (0-100) | Notes |
|---|---:|---|
| Agent-Readiness | 91 | Strong tool set, strong routing/composability, improved schemas; examples still missing |
| Data Accuracy | 90 | Sampled points aligned; one FDA recency issue fixed during audit |
| Optimization | 82 | Good sanitization/error handling; high token payloads and LIKE scans for some paths |
| Deployment Maturity | 90 | CI/CD, publish provenance, 6-layer security workflows, registry metadata alignment |
| Overall Grade | **A-** | One critical portability gap prevents A/A+ |

## 4) Critical Findings (Production Blockers)

1. **WASM SQLite portability gap (FAIL)**  
   The implementation uses native `better-sqlite3` (`/Users/jeffreyvonrotz/Projects/Healthcare-mcp/package.json:64`, `/Users/jeffreyvonrotz/Projects/Healthcare-mcp/src/db.ts:1`) while this audit standard requires a WASM SQLite strategy for serverless reliability.

## 5) Top 10 Improvements (Prioritized)

1. **Migrate DB runtime to WASM SQLite adapter** (critical portability fix).  
   Touchpoints: `/Users/jeffreyvonrotz/Projects/Healthcare-mcp/src/db.ts:1`, `/Users/jeffreyvonrotz/Projects/Healthcare-mcp/package.json:62`.
2. **Add schema examples for every tool input** to improve zero-shot tool calling.  
   Touchpoint: `/Users/jeffreyvonrotz/Projects/Healthcare-mcp/src/tools/registry.ts:331`.
3. **Add response detail-level controls** (`summary|standard|full`) for heavy tools to reduce token cost.  
   Touchpoints: `/Users/jeffreyvonrotz/Projects/Healthcare-mcp/src/tools/assess_healthcare_applicability.ts:1`, `/Users/jeffreyvonrotz/Projects/Healthcare-mcp/src/tools/get_healthcare_threats.ts:113`.
4. **Add pagination cursor support** on threat and search tools for long result sets.  
   Touchpoints: `/Users/jeffreyvonrotz/Projects/Healthcare-mcp/src/tools/get_healthcare_threats.ts:113`, `/Users/jeffreyvonrotz/Projects/Healthcare-mcp/src/tools/search_domain_knowledge.ts:15`.
5. **Replace `LIKE` search with indexed FTS for architecture/standards** for growth headroom.  
   Touchpoint: `/Users/jeffreyvonrotz/Projects/Healthcare-mcp/src/tools/search_domain_knowledge.ts:83`.
6. **Convert source freshness check from static date parsing to authoritative HEAD/API checks**.  
   Touchpoint: `/Users/jeffreyvonrotz/Projects/Healthcare-mcp/scripts/check-source-updates.ts:12`.
7. **Enforce live authoritative regression as required in CI for release tags** (with fallback matrix but fail policy).  
   Touchpoint: `/Users/jeffreyvonrotz/Projects/Healthcare-mcp/.github/workflows/live-authoritative-regression.yml:1`.
8. **Add coverage gate (`vitest --coverage`) and minimum thresholds**.  
   Touchpoint: `/Users/jeffreyvonrotz/Projects/Healthcare-mcp/package.json:29`.
9. **Add explicit “in-scope vs not-indexed” status field across query tools** for clearer orchestration semantics.  
   Touchpoint: `/Users/jeffreyvonrotz/Projects/Healthcare-mcp/src/tools/search_domain_knowledge.ts:112`.
10. **Add release-time registry visibility/version sync check** against MCP registry + npm to prevent metadata drift.  
    Touchpoint: `/Users/jeffreyvonrotz/Projects/Healthcare-mcp/.github/workflows/publish.yml:33`.

## 6) Risk Assessment

- If agents rely on this server for production healthcare decisions, the major residual risk is **runtime portability/availability** (native SQLite driver in serverless constraints).
- Secondary risks are **context window pressure** (large payloads from baseline/applicability tools) and **freshness confidence risk** from static provenance dates.
- Regulatory interpretation risk is moderated by the router model, but only if upstream authoritative MCP calls are actually executed in workflows.

## 7) Server-Specific Notes

- This MCP is correctly positioned as a **domain router + ontology layer**, not as a legal text authority.
- Coverage is broad for EU/US baseline routing but deep member-state/state overlays are still selective; this is acceptable if disclosed (it is disclosed).
- Audit-grade value is strongest when `resolve_authoritative_context` and live upstream tests are enforced in operational pipelines.
