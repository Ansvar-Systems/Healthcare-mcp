import type { SqlDatabase } from '../db.js';
import { EU_COUNTRY_CODES, US_STATE_CODES } from '../jurisdictions.js';
import type { AboutContext } from '../types.js';
import { responseMeta } from './response-meta.js';

function safeCount(db: SqlDatabase, sql: string): number {
  try {
    const row = db.prepare(sql).get() as { count: number } | undefined;
    return row ? Number(row.count) : 0;
  } catch {
    return 0;
  }
}

export function getAbout(db: SqlDatabase, context: AboutContext) {
  const counts = {
    health_data_categories: safeCount(db, 'SELECT COUNT(*) as count FROM health_data_categories'),
    architecture_patterns: safeCount(db, 'SELECT COUNT(*) as count FROM architecture_patterns'),
    threat_scenarios: safeCount(db, 'SELECT COUNT(*) as count FROM threat_scenarios'),
    threat_expert_profiles: safeCount(db, 'SELECT COUNT(*) as count FROM threat_expert_profiles'),
    threat_response_playbooks: safeCount(db, 'SELECT COUNT(*) as count FROM threat_response_playbooks'),
    technical_standards: safeCount(db, 'SELECT COUNT(*) as count FROM technical_standards'),
    obligation_profiles: safeCount(db, 'SELECT COUNT(*) as count FROM obligation_profiles'),
    jurisdiction_overlays: safeCount(db, 'SELECT COUNT(*) as count FROM jurisdiction_overlays'),
    evidence_templates: safeCount(db, 'SELECT COUNT(*) as count FROM evidence_templates'),
  };

  const metadataRows = db
    .prepare('SELECT key, value FROM db_metadata ORDER BY key')
    .all() as Array<{ key: string; value: string }>;

  const metadata = Object.fromEntries(metadataRows.map((row) => [row.key, row.value]));
  const overlayCountries = (
    db.prepare('SELECT DISTINCT country_code FROM jurisdiction_overlays ORDER BY country_code').all() as Array<{
      country_code: string;
    }>
  ).map((row) => row.country_code);

  return {
    server: {
      name: 'Healthcare Intelligence MCP',
      package: '@ansvar/healthcare-mcp',
      version: context.version,
      suite: 'Ansvar Compliance Suite',
      repository: 'https://github.com/Ansvar-Systems/Healthcare-mcp',
    },
    dataset: {
      fingerprint: context.fingerprint,
      built: context.dbBuilt,
      regions: ['US', 'EU'],
      content_basis:
        'Healthcare ontology and crosswalk metadata for threat modeling. Authoritative regulation/control text is delegated to specialized MCPs.',
      counts,
      metadata,
    },
    coverage_summary: {
      jurisdictions_supported: {
        eu_member_states: EU_COUNTRY_CODES.size,
        us_states_and_dc: US_STATE_CODES.size,
      },
      explicit_overlay_countries: overlayCountries,
      synthesized_fallback: 'EU member-state and US state/DC fallback obligations are generated when explicit packs are missing.',
    },
    composition: {
      role: 'domain_router',
      upstream_mcps: [
        'EU_Regulations_MCP',
        'US_Regulations_MCP',
        'Security_Controls_MCP',
        'US-law-mcp',
        'EU member-state law MCPs',
      ],
      delegation_note:
        'This MCP classifies context and routes references. It does not claim to be the canonical legal text source.',
    },
    assurance: {
      freshness_model: 'metadata-indexed with scheduled source checks',
      required_validation: [
        'Phase 2 sampling against authoritative source text in linked MCPs',
        'Golden tests for routing and mapping integrity',
        'Drift detection for crosswalk stability',
      ],
    },
    known_limitations: [
      'Synthesized fallback obligations are inferential and must be confirmed through upstream regulation/law MCP calls.',
      'Country-specific overlays are currently deepened for SE, DE, US-CA, and US-TX; others default to jurisdiction-family baseline.',
    ],
    ...responseMeta(),
  };
}
