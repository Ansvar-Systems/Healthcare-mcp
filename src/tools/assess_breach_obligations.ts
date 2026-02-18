import type { SqlDatabase } from '../db.js';
import { parseJsonArray } from '../db.js';
import { jurisdictionFamily, normalizeJurisdictionCode } from '../jurisdictions.js';
import type { AssessBreachObligationsInput, ToolError } from '../types.js';

type BreachRuleRow = {
  rule_id: string;
  jurisdiction: string;
  trigger_category: string;
  deadline_hours: number;
  notify_parties: string;
  content_requirements: string;
  source_router: string;
};

function normalizeJurisdiction(input: string): string {
  return normalizeJurisdictionCode(input);
}

function isHighSensitivityCategory(category: string): boolean {
  return [
    'ephi',
    'health_data',
    'special_category_health_data',
    'part2_substance_use',
    'mental_health',
    'reproductive_health',
    'pediatric_health',
    'genetic_data',
    'genomic_biobank_data',
    'ehds_secondary_use',
    'ehds_primary_use',
    'imaging_data',
    'prescription_data',
  ].includes(category);
}

function isMajorIncident(summary: string): boolean {
  const lowered = summary.toLowerCase();
  return [
    'ransomware',
    'major incident',
    'patient diversion',
    'critical outage',
    'downtime',
    'clinical operations disrupted',
  ].some((token) => lowered.includes(token));
}

function ruleApplies(
  triggerCategory: string,
  categories: Set<string>,
  summary: string,
): boolean {
  const loweredSummary = summary.toLowerCase();
  const highSensitivity = [...categories].some((category) => isHighSensitivityCategory(category));

  switch (triggerCategory) {
    case 'ephi':
      return categories.has('ephi') || categories.has('health_data') || highSensitivity;
    case 'part2_substance_use':
      return categories.has('part2_substance_use') || loweredSummary.includes('substance');
    case 'special_category_health_data':
      return highSensitivity;
    case 'essential_entity_major_incident':
      return isMajorIncident(summary) || highSensitivity;
    case 'state_health_privacy':
      return highSensitivity || loweredSummary.includes('medical') || loweredSummary.includes('health');
    case 'member_state_healthcare_data':
      return highSensitivity;
    case 'ehds_secondary_use':
      return categories.has('ehds_secondary_use') || loweredSummary.includes('secondary use');
    default:
      return true;
  }
}

function jurisdictionCandidates(jurisdiction: string): string[] {
  const normalized = normalizeJurisdiction(jurisdiction);
  const candidates = [normalized];
  const family = jurisdictionFamily(normalized);
  if (family === 'US') {
    candidates.push('US');
  } else if (family === 'EU') {
    candidates.push('EU');
  }
  return [...new Set(candidates)];
}

export function assessBreachObligations(
  db: SqlDatabase,
  args: unknown,
): Record<string, unknown> | ToolError {
  const input = args as AssessBreachObligationsInput & {
    incident_description?: string;
    data_types?: string[];
  };
  const incidentSummary = input.incident_summary ?? input.incident_description ?? '';
  const dataCategories = input.data_categories ?? input.data_types ?? [];

  if (!input?.jurisdictions?.length || !dataCategories?.length || !incidentSummary) {
    return {
      error: 'jurisdictions, data_categories, and incident_summary are required',
      hint: 'Example jurisdictions: ["US", "EU"]. Include whether health data and clinical impact are present.',
    };
  }

  const normalizedJurisdictions = [...new Set(input.jurisdictions.map(normalizeJurisdiction))];
  const normalizedCategories = new Set(dataCategories.map((category) => category.trim().toLowerCase()).filter(Boolean));

  const rows = db
    .prepare(
      `SELECT rule_id, jurisdiction, trigger_category, deadline_hours, notify_parties,
              content_requirements, source_router
       FROM breach_rules
       ORDER BY deadline_hours ASC`,
    )
    .all() as BreachRuleRow[];

  const timeline: Array<Record<string, unknown>> = [];

  for (const requestedJurisdiction of normalizedJurisdictions) {
    const candidates = jurisdictionCandidates(requestedJurisdiction);
    const applicableRules = rows.filter(
      (row) =>
        candidates.includes(normalizeJurisdiction(row.jurisdiction)) &&
        ruleApplies(row.trigger_category, normalizedCategories, incidentSummary),
    );

    for (const rule of applicableRules) {
      timeline.push({
        rule_id: rule.rule_id,
        requested_jurisdiction: requestedJurisdiction,
        rule_jurisdiction: normalizeJurisdiction(rule.jurisdiction),
        trigger_category: rule.trigger_category,
        deadline_hours: rule.deadline_hours,
        deadline_days: Number((rule.deadline_hours / 24).toFixed(2)),
        notify_parties: parseJsonArray(rule.notify_parties),
        content_requirements: parseJsonArray(rule.content_requirements),
        source_router: rule.source_router,
        confidence:
          normalizeJurisdiction(rule.jurisdiction) === requestedJurisdiction ? 'inferred' : 'estimated',
      });
    }
  }

  const dedupedTimeline = Array.from(
    new Map(
      timeline.map((item) => [
        `${String(item.requested_jurisdiction)}|${String(item.rule_id)}|${String(item.deadline_hours)}`,
        item,
      ]),
    ).values(),
  ).sort((a, b) => Number(a.deadline_hours) - Number(b.deadline_hours));

  const healthCritical = [...normalizedCategories].some((category) => isHighSensitivityCategory(category));

  const strictest = dedupedTimeline[0] ?? null;
  const perJurisdiction = normalizedJurisdictions.map((jurisdiction) => {
    const entries = dedupedTimeline.filter((item) => item.requested_jurisdiction === jurisdiction);
    const earliest = entries[0] ?? null;
    return {
      jurisdiction,
      strictest_deadline_hours: earliest?.deadline_hours ?? null,
      notifications: entries,
    };
  });

  const immediateReview = healthCritical || dedupedTimeline.some((item) => Number(item.deadline_hours) <= 72);

  return {
    incident_summary: incidentSummary,
    data_categories: dataCategories,
    notifications: dedupedTimeline,
    jurisdictions: normalizedJurisdictions,
    strictest_deadline: strictest,
    timeline: dedupedTimeline,
    notification_matrix: perJurisdiction,
    decision_tree: [
      {
        step: 1,
        action: 'Normalize jurisdictions and data categories.',
        result: {
          jurisdictions: normalizedJurisdictions,
          data_categories: [...normalizedCategories],
        },
      },
      {
        step: 2,
        action: 'Evaluate healthcare sensitivity and incident criticality.',
        result: {
          high_sensitivity_health_data: healthCritical,
          major_incident_signal: isMajorIncident(incidentSummary),
        },
      },
      {
        step: 3,
        action: 'Apply exact-jurisdiction and family fallback breach rules.',
        result: {
          matched_rules: dedupedTimeline.length,
          strictest_deadline_hours: strictest?.deadline_hours ?? null,
        },
      },
      {
        step: 4,
        action: 'Route to authoritative MCP sources for final legal text and thresholds.',
        result: {
          source_routes: [...new Set(dedupedTimeline.map((item) => String(item.source_router)))],
        },
      },
    ],
    escalation_flags: {
      high_severity_health_data: healthCritical,
      immediate_legal_review: immediateReview,
      overlapping_jurisdiction_obligations: perJurisdiction.some((item) => item.notifications.length > 1),
    },
    penalty_exposure: {
      level: immediateReview ? 'high' : 'moderate',
      drivers: immediateReview
        ? ['Short reporting windows', 'Sensitive healthcare data categories']
        : ['Baseline reporting obligations apply'],
    },
    next_actions: [
      'Confirm reportability by calling relevant regulation MCP with cited references.',
      'Generate notification package fields from content_requirements.',
      'Start evidence preservation and incident chronology capture in parallel.',
    ],
  };
}
