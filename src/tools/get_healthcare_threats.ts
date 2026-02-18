import type Database from 'better-sqlite3';
import { parseJsonArray } from '../db.js';
import type { GetHealthcareThreatsInput, ToolError } from '../types.js';

type ThreatRow = {
  threat_id: string;
  name: string;
  pattern_id: string | null;
  description: string;
  attack_path: string;
  clinical_impact: string;
  business_impact: string;
  severity: 'critical' | 'high' | 'moderate' | 'low';
  mitre_tactics: string;
  mitigations: string;
};

type ThreatExpertRow = {
  mitre_techniques: string;
  likelihood_factors: string;
  exploit_preconditions: string;
  detection_indicators: string;
  historical_incidents: string;
};

type ThreatPlaybookRow = {
  triage_priority: 'P1' | 'P2' | 'P3';
  immediate_containment_actions: string;
  clinical_safety_actions: string;
  forensic_artifacts: string;
  recovery_validation_checks: string;
  communication_requirements: string;
  escalation_routes: string;
};

function sanitizeFtsQuery(query: string): string {
  return query.replace(/[^a-zA-Z0-9\s]/g, ' ').trim().replace(/\s+/g, ' ');
}

function withLinks(db: Database.Database, threat: ThreatRow) {
  const regulationLinks = db
    .prepare(
      `SELECT source_mcp, requirement_ref, obligation_summary
       FROM threat_regulation_links WHERE threat_id = ? ORDER BY source_mcp, requirement_ref`,
    )
    .all(threat.threat_id) as Array<{
    source_mcp: string;
    requirement_ref: string;
    obligation_summary: string;
  }>;

  const controlLinks = db
    .prepare(
      `SELECT control_framework, control_id, control_summary
       FROM threat_control_links WHERE threat_id = ? ORDER BY control_framework, control_id`,
    )
    .all(threat.threat_id) as Array<{
    control_framework: string;
    control_id: string;
    control_summary: string;
  }>;

  const expert = db
    .prepare(
      `SELECT mitre_techniques, likelihood_factors, exploit_preconditions,
              detection_indicators, historical_incidents
       FROM threat_expert_profiles
       WHERE threat_id = ?`,
    )
    .get(threat.threat_id) as ThreatExpertRow | undefined;

  const playbook = db
    .prepare(
      `SELECT triage_priority, immediate_containment_actions, clinical_safety_actions,
              forensic_artifacts, recovery_validation_checks, communication_requirements, escalation_routes
       FROM threat_response_playbooks
       WHERE threat_id = ?`,
    )
    .get(threat.threat_id) as ThreatPlaybookRow | undefined;

  return {
    threat_id: threat.threat_id,
    name: threat.name,
    pattern_id: threat.pattern_id,
    description: threat.description,
    attack_path: threat.attack_path,
    clinical_impact: threat.clinical_impact,
    business_impact: threat.business_impact,
    severity: threat.severity,
    mitre_tactics: parseJsonArray(threat.mitre_tactics),
    mitre_techniques: expert ? parseJsonArray(expert.mitre_techniques) : [],
    likelihood_factors: expert ? parseJsonArray(expert.likelihood_factors) : [],
    exploit_preconditions: expert ? parseJsonArray(expert.exploit_preconditions) : [],
    detection_indicators: expert ? parseJsonArray(expert.detection_indicators) : [],
    historical_incidents: expert ? parseJsonArray(expert.historical_incidents) : [],
    response_playbook: playbook
      ? {
          triage_priority: playbook.triage_priority,
          immediate_containment_actions: parseJsonArray(playbook.immediate_containment_actions),
          clinical_safety_actions: parseJsonArray(playbook.clinical_safety_actions),
          forensic_artifacts: parseJsonArray(playbook.forensic_artifacts),
          recovery_validation_checks: parseJsonArray(playbook.recovery_validation_checks),
          communication_requirements: parseJsonArray(playbook.communication_requirements),
          escalation_routes: parseJsonArray(playbook.escalation_routes),
        }
      : null,
    mitigations: parseJsonArray(threat.mitigations),
    linked_regulatory_routes: regulationLinks,
    linked_control_routes: controlLinks,
  };
}

export function getHealthcareThreats(
  db: Database.Database,
  args: unknown,
): Record<string, unknown> | ToolError {
  const input = (args ?? {}) as GetHealthcareThreatsInput & {
    architecture_pattern?: string;
    data_types?: string[];
    deployment_context?: string;
  };
  const includePlaybooks = input.include_playbooks ?? true;
  const patternId = input.pattern_id ?? input.architecture_pattern;
  const dataTypes = input.data_categories ?? input.data_types ?? [];
  const limit = Math.max(1, Math.min(50, input.limit ?? 10));

  let threats: ThreatRow[] = [];

  if (input.query && input.query.trim().length > 0) {
    const clean = sanitizeFtsQuery(input.query);
    if (clean.length === 0) {
      return {
        error: 'query must contain searchable text after sanitization',
        hint: 'Use plain words and avoid raw FTS operators.',
      };
    }

    threats = db
      .prepare(
        `SELECT t.threat_id, t.name, t.pattern_id, t.description, t.attack_path, t.clinical_impact,
                t.business_impact, t.severity, t.mitre_tactics, t.mitigations
         FROM threat_scenarios_fts f
         JOIN threat_scenarios t ON t.rowid = f.rowid
         WHERE threat_scenarios_fts MATCH ?
         ORDER BY rank
         LIMIT ?`,
      )
      .all(clean, limit) as ThreatRow[];
  } else if (patternId) {
    threats = db
      .prepare(
        `SELECT threat_id, name, pattern_id, description, attack_path, clinical_impact,
                business_impact, severity, mitre_tactics, mitigations
         FROM threat_scenarios
         WHERE pattern_id = ? OR pattern_id IS NULL
         ORDER BY CASE severity
           WHEN 'critical' THEN 1
           WHEN 'high' THEN 2
           WHEN 'moderate' THEN 3
           ELSE 4
         END, threat_id
         LIMIT ?`,
      )
      .all(patternId, limit) as ThreatRow[];
  } else {
    threats = db
      .prepare(
        `SELECT threat_id, name, pattern_id, description, attack_path, clinical_impact,
                business_impact, severity, mitre_tactics, mitigations
         FROM threat_scenarios
         ORDER BY CASE severity
           WHEN 'critical' THEN 1
           WHEN 'high' THEN 2
           WHEN 'moderate' THEN 3
           ELSE 4
         END, threat_id
         LIMIT ?`,
      )
      .all(limit) as ThreatRow[];
  }

  const enriched = threats.map((threat) => {
    const full = withLinks(db, threat);
    if (includePlaybooks) {
      return full;
    }
    return {
      ...full,
      response_playbook: null,
    };
  });

  const dataCategoryFilter = dataTypes;
  const filtered =
    dataCategoryFilter.length === 0
      ? enriched
      : enriched.filter((threat) =>
          threat.linked_regulatory_routes.some((route) =>
            dataCategoryFilter.some((category) => route.requirement_ref.toLowerCase().includes(category.toLowerCase())),
          ),
        );

  return {
    criteria: {
      pattern_id: patternId ?? null,
      query: input.query ?? null,
      data_categories: dataCategoryFilter,
      deployment_context: input.deployment_context ?? null,
      include_playbooks: includePlaybooks,
      limit,
    },
    threats: filtered,
    mitre_mapping: filtered.map((threat) => ({
      threat_id: threat.threat_id,
      techniques: threat.mitre_tactics,
      attack_techniques: threat.mitre_techniques,
    })),
    count: filtered.length,
    note:
      'Threats include healthcare context, ATT&CK tactics/techniques, detection indicators, and response playbooks with regulation/control routing references.',
  };
}
