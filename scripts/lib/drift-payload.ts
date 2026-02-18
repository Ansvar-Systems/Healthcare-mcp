import { createHash } from 'node:crypto';
import type Database from 'better-sqlite3';

export interface HashEntry {
  id: string;
  description: string;
  hash: string;
  sample: unknown;
}

export interface DriftPayload {
  version: string;
  generated_at: string;
  description: string;
  hashes: HashEntry[];
}

function stableHash(value: unknown): string {
  const serialized = JSON.stringify(value);
  return createHash('sha256').update(serialized).digest('hex');
}

export function buildDriftPayload(db: Database.Database, version = '0.1.0'): DriftPayload {
  const entries: HashEntry[] = [];

  const tableCounts = db
    .prepare(
      `SELECT 'architecture_patterns' as table_name, COUNT(*) as count FROM architecture_patterns
       UNION ALL
       SELECT 'health_data_categories', COUNT(*) FROM health_data_categories
       UNION ALL
       SELECT 'obligation_profiles', COUNT(*) FROM obligation_profiles
       UNION ALL
       SELECT 'jurisdiction_overlays', COUNT(*) FROM jurisdiction_overlays
       UNION ALL
       SELECT 'technical_standards', COUNT(*) FROM technical_standards
       UNION ALL
       SELECT 'threat_scenarios', COUNT(*) FROM threat_scenarios
       UNION ALL
       SELECT 'threat_expert_profiles', COUNT(*) FROM threat_expert_profiles
       UNION ALL
       SELECT 'threat_response_playbooks', COUNT(*) FROM threat_response_playbooks
       ORDER BY table_name`,
    )
    .all() as Array<{ table_name: string; count: number }>;

  entries.push({
    id: 'table_counts',
    description: 'Core ontology table counts',
    hash: stableHash(tableCounts),
    sample: tableCounts,
  });

  const patternIds = db
    .prepare('SELECT pattern_id FROM architecture_patterns ORDER BY pattern_id')
    .all();

  entries.push({
    id: 'architecture_pattern_ids',
    description: 'Supported architecture pattern identifiers',
    hash: stableHash(patternIds),
    sample: patternIds,
  });

  const criticalCategories = db
    .prepare(
      `SELECT category_id, name, sensitivity_tier
       FROM health_data_categories
       WHERE sensitivity_tier = 'critical'
       ORDER BY category_id`,
    )
    .all();

  entries.push({
    id: 'critical_data_categories',
    description: 'Critical healthcare data category identity set',
    hash: stableHash(criticalCategories),
    sample: criticalCategories,
  });

  const threatRouteCoverage = db
    .prepare(
      `SELECT threat_id, source_mcp, requirement_ref
       FROM threat_regulation_links
       ORDER BY threat_id, source_mcp, requirement_ref`,
    )
    .all();

  entries.push({
    id: 'threat_regulation_routes',
    description: 'Threat to regulation route mappings',
    hash: stableHash(threatRouteCoverage),
    sample: threatRouteCoverage,
  });

  const threatExpertCoverage = db
    .prepare(
      `SELECT threat_id,
              json_array_length(mitre_techniques) as mitre_technique_count,
              json_array_length(likelihood_factors) as likelihood_factor_count,
              json_array_length(detection_indicators) as detection_indicator_count
       FROM threat_expert_profiles
       ORDER BY threat_id`,
    )
    .all();

  entries.push({
    id: 'threat_expert_profiles',
    description: 'Threat expert intelligence profile coverage (MITRE techniques, likelihood, detection)',
    hash: stableHash(threatExpertCoverage),
    sample: threatExpertCoverage,
  });

  const threatPlaybookCoverage = db
    .prepare(
      `SELECT threat_id,
              triage_priority,
              json_array_length(immediate_containment_actions) as containment_count,
              json_array_length(clinical_safety_actions) as clinical_safety_count,
              json_array_length(forensic_artifacts) as forensic_count,
              json_array_length(recovery_validation_checks) as recovery_count
       FROM threat_response_playbooks
       ORDER BY threat_id`,
    )
    .all();

  entries.push({
    id: 'threat_response_playbooks',
    description: 'Threat response playbook coverage (containment, clinical safety, forensics, recovery)',
    hash: stableHash(threatPlaybookCoverage),
    sample: threatPlaybookCoverage,
  });

  const overlayCoverage = db
    .prepare(
      `SELECT country_code, COUNT(*) as count
       FROM jurisdiction_overlays
       GROUP BY country_code
       ORDER BY country_code`,
    )
    .all();

  entries.push({
    id: 'jurisdiction_overlay_coverage',
    description: 'Explicit jurisdiction overlay coverage by country code',
    hash: stableHash(overlayCoverage),
    sample: overlayCoverage,
  });

  return {
    version,
    generated_at: new Date().toISOString(),
    description:
      'Deterministic hashes for Healthcare MCP ontology and crosswalk subsets. Use in CI for drift detection.',
    hashes: entries,
  };
}
