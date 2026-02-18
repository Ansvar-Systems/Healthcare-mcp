import type Database from 'better-sqlite3';
import { EU_COUNTRY_CODES, US_STATE_CODES } from '../jurisdictions.js';

export function listProfiles(db: Database.Database, args: unknown) {
  const input = (args ?? {}) as {
    profile_type?:
      | 'data_categories'
      | 'architecture_patterns'
      | 'threat_expert_profiles'
      | 'threat_response_playbooks'
      | 'obligation_profiles'
      | 'jurisdiction_overlays'
      | 'jurisdiction_coverage'
      | 'all';
  };
  const profileType = input.profile_type ?? 'all';

  const result: Record<string, unknown> = {};

  if (profileType === 'all' || profileType === 'data_categories') {
    result.data_categories = db
      .prepare(
        'SELECT category_id, name, sensitivity_tier FROM health_data_categories ORDER BY sensitivity_tier, category_id',
      )
      .all();
  }

  if (profileType === 'all' || profileType === 'architecture_patterns') {
    result.architecture_patterns = db
      .prepare('SELECT pattern_id, name, primary_system FROM architecture_patterns ORDER BY pattern_id')
      .all();
  }

  if (profileType === 'all' || profileType === 'threat_expert_profiles') {
    result.threat_expert_profiles = db
      .prepare(
        `SELECT threat_id,
                json_array_length(mitre_techniques) as mitre_technique_count,
                json_array_length(likelihood_factors) as likelihood_factor_count,
                json_array_length(detection_indicators) as detection_indicator_count
         FROM threat_expert_profiles
         ORDER BY threat_id`,
      )
      .all();
  }

  if (profileType === 'all' || profileType === 'threat_response_playbooks') {
    result.threat_response_playbooks = db
      .prepare(
        `SELECT threat_id,
                triage_priority,
                json_array_length(immediate_containment_actions) as containment_action_count,
                json_array_length(clinical_safety_actions) as clinical_safety_action_count,
                json_array_length(forensic_artifacts) as forensic_artifact_count
         FROM threat_response_playbooks
         ORDER BY threat_id`,
      )
      .all();
  }

  if (profileType === 'all' || profileType === 'obligation_profiles') {
    result.obligation_profiles = db
      .prepare(
        'SELECT profile_id, name, jurisdiction, entity_type, priority FROM obligation_profiles ORDER BY priority, profile_id',
      )
      .all();
  }

  if (profileType === 'all' || profileType === 'jurisdiction_overlays') {
    result.jurisdiction_overlays = db
      .prepare(
        `SELECT overlay_id, country_code, role, system_type, data_type, priority, source_router
         FROM jurisdiction_overlays
         ORDER BY country_code, overlay_id`,
      )
      .all();
  }

  if (profileType === 'all' || profileType === 'jurisdiction_coverage') {
    const explicitOverlayCountries = (
      db
        .prepare('SELECT DISTINCT country_code FROM jurisdiction_overlays ORDER BY country_code')
        .all() as Array<{ country_code: string }>
    ).map((row) => row.country_code);

    result.jurisdiction_coverage = {
      eu_member_states: [...EU_COUNTRY_CODES].sort(),
      us_states_and_dc: [...US_STATE_CODES].map((code) => `US-${code}`).sort(),
      explicit_overlay_countries: explicitOverlayCountries,
      synthesized_fallback_enabled: true,
    };
  }

  return result;
}
