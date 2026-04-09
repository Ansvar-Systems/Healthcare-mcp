# Healthcare Intelligence MCP — Coverage

## Corpus Overview

This MCP provides a **frozen SQLite corpus** of healthcare domain-intelligence metadata for threat modeling, regulatory awareness, and standards crosswalk. It is not authoritative legal text — see [sources.yml](sources.yml) for source provenance and upstream delegation routes.

| Dimension | Detail |
|---|---|
| **Corpus type** | Frozen SQLite — static at build time |
| **Data obtained** | 2026-02-18 |
| **Schema version** | See `db_metadata` (`about` tool) |
| **Seed files** | 11 JSON files in `data/seed/` |
| **EU jurisdictions** | 27 member states |
| **US jurisdictions** | 50 states + DC (51 total) |
| **Coverage basis** | Threat modeling metadata, crosswalk references, and regulatory routing — not authoritative legal text |

## Seed Data Files

| File | Content |
|---|---|
| `health_data_categories.json` | Healthcare data classification taxonomy (9 categories) |
| `threat_scenarios.json` | Healthcare-specific attack scenarios with MITRE ATT&CK mappings |
| `threat_expert_profiles.json` | Expert threat profiles: techniques, preconditions, detection indicators |
| `threat_response_playbooks.json` | Incident response playbooks by threat ID |
| `threat_links.json` | Threat-to-regulation and threat-to-control routing links |
| `architecture_patterns.json` | Healthcare system topology archetypes (EHR, FHIR, DICOM/PACS, IoMT, etc.) |
| `obligation_profiles.json` | Base jurisdiction/entity obligation profiles |
| `jurisdiction_overlays.json` | Deep-pack overlays for SE, DE, US-CA, US-TX, NL |
| `technical_standards.json` | Healthcare technical standards library (HL7, IEC, ISO, NIST, etc.) |
| `evidence_templates.json` | Audit evidence templates (MDR/IVDR, ISO 27001, HITRUST, AI Act) |
| `breach_rules.json` | Breach notification timelines and party requirements by jurisdiction |
| `medical_device_rules.json` | FDA/MDR classification rules with keyword triggers |

> Note: `medical_device_rules.json` is the 12th file on disk. The 11 seed files above cover the primary ontology.

## Jurisdiction Coverage

### EU Member States (27)
AT, BE, BG, HR, CY, CZ, DK, EE, FI, FR, DE, GR, HU, IE, IT, LV, LT, LU, MT, NL, PL, PT, RO, SK, SI, ES, SE

**Explicit deep-pack overlays:** DE, NL, SE (EU member states)

### US States + DC (51)
All 50 US states plus DC. Jurisdiction codes use the `US-XX` format (e.g., `US-CA`, `US-TX`).

**Explicit deep-pack overlays:** US-CA, US-TX

### Synthesized Fallback
For jurisdictions without explicit overlays, the MCP generates synthesized obligations derived from the jurisdiction-family baseline:
- **EU family:** GDPR + NIS2 + AI Act baseline
- **US family:** HIPAA + state law routing + FDA baseline

Synthesized obligations are marked `confidence: estimated` and must be validated via upstream regulation/law MCPs before use in compliance decisions.

## Coverage Limitations

- **Threat modeling metadata only** — this corpus provides routing references and domain context, not canonical legal text.
- **Authoritative text is delegated** to specialized upstream MCPs: `EU_Regulations_MCP`, `US_Regulations_MCP`, `Security_Controls_MCP`, `US-law-mcp`, and member-state law MCPs.
- **Frozen corpus** — content does not update automatically. The `check_data_freshness` tool reports corpus age against the 45-day staleness threshold.
- **Overlay depth varies** — SE, DE, US-CA, and US-TX have deeper country/state-specific overlays; other jurisdictions rely on synthesized fallback.

## Freshness

| Metric | Value |
|---|---|
| Data obtained | 2026-02-18 |
| Staleness threshold | 45 days |
| Freshness check | `check_data_freshness` tool or `check-freshness.yml` workflow |
