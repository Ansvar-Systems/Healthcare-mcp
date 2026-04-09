import type { SqlDatabase } from '../db.js';
import { parseJsonArray } from '../db.js';
import { isEuJurisdiction, isUsJurisdiction, normalizeJurisdictionCode } from '../jurisdictions.js';
import type { ClassifyHealthDataInput, ToolError } from '../types.js';
import { responseMeta } from './response-meta.js';

type CategoryRow = {
  category_id: string;
  name: string;
  description: string;
  sensitivity_tier: 'critical' | 'high' | 'moderate';
  us_regimes: string;
  eu_regimes: string;
  notes: string | null;
};

function tokenize(value: string): string[] {
  return value
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((token) => token.length >= 3);
}

function scoreMatch(haystack: string, tokens: string[]): number {
  let score = 0;
  for (const token of tokens) {
    if (haystack.includes(token)) {
      score += 1;
    }
  }
  return score;
}

function normalizeJurisdiction(input: string): string {
  return normalizeJurisdictionCode(input);
}

export function classifyHealthData(
  db: SqlDatabase,
  args: unknown,
): Record<string, unknown> | ToolError {
  const input = args as ClassifyHealthDataInput & { data_description?: string };
  const description = input?.description ?? input?.data_description ?? '';

  if (description.trim().length < 8) {
    return {
      error: 'description must be provided and include enough detail to classify data categories',
      hint: 'Include examples like patient diagnoses, imaging data, genomic records, or care workflow logs.',
      _error_type: 'invalid_input',
      ...responseMeta(),
    };
  }

  const rows = db.prepare(`
    SELECT category_id, name, description, sensitivity_tier, us_regimes, eu_regimes, notes
    FROM health_data_categories
    ORDER BY category_id
  `).all() as CategoryRow[];

  const tokens = tokenize(description);
  const matched = rows
    .map((row) => {
      const haystack = `${row.category_id} ${row.name} ${row.description} ${row.notes ?? ''}`.toLowerCase();
      return {
        ...row,
        score: scoreMatch(haystack, tokens),
      };
    })
    .filter((row) => row.score > 0)
    .sort((a, b) => b.score - a.score);

  const selected = matched.length > 0 ? matched : rows.slice(0, 2).map((row) => ({ ...row, score: 0 }));

  const classified = selected.map((row) => ({
    category_id: row.category_id,
    name: row.name,
    sensitivity_tier: row.sensitivity_tier,
    reasoning:
      matched.length > 0
        ? `Matched ${row.score} description keywords`
        : 'Default high-sensitivity fallback due low-confidence match',
    us_regimes: parseJsonArray(row.us_regimes),
    eu_regimes: parseJsonArray(row.eu_regimes),
    notes: row.notes,
  }));

  const regimes = {
    US: [...new Set(classified.flatMap((item) => item.us_regimes))],
    EU: [...new Set(classified.flatMap((item) => item.eu_regimes))],
  };

  const jurisdictions = (input.jurisdictions ?? ['US', 'EU']).map(normalizeJurisdiction);
  const jurisdictionSpecific: string[] = [];
  const loweredDescription = description.toLowerCase();

  if (jurisdictions.some((item) => isUsJurisdiction(item))) {
    jurisdictionSpecific.push('HIPAA_164.312');
  }
  if (jurisdictions.some((item) => isEuJurisdiction(item))) {
    jurisdictionSpecific.push('GDPR_ART_9');
  }

  if (jurisdictions.includes('SE') || loweredDescription.includes('swedish') || loweredDescription.includes('sweden')) {
    jurisdictionSpecific.push('SE_PATIENTDATALAGEN');
  }
  if (jurisdictions.includes('DE') || loweredDescription.includes('german') || loweredDescription.includes('germany')) {
    jurisdictionSpecific.push('BDSG_HEALTH_DATA');
  }
  if (jurisdictions.includes('US-CA') || loweredDescription.includes('california')) {
    jurisdictionSpecific.push('CA_CMIA', 'CCPA_1798.100');
  }
  if (jurisdictions.includes('US-NY') || loweredDescription.includes('new york')) {
    jurisdictionSpecific.push('NY_MENTAL_HYGIENE_LAW', 'NY_SHIELD_ACT');
  }

  const handlingRequirements = [
    'Apply least-privilege access and audited access logging.',
    'Enforce encryption for storage and transmission paths.',
    'Validate disclosure and cross-border transfer constraints before data sharing.',
  ];

  return {
    input_summary: description,
    jurisdictions_considered: jurisdictions,
    categories: classified,
    applicable_regimes: [...new Set([...regimes.US, ...regimes.EU, ...jurisdictionSpecific])],
    protection_tier: classified.some((item) => item.sensitivity_tier === 'critical')
      ? 'critical'
      : 'high',
    likely_regimes: regimes,
    handling_requirements: handlingRequirements,
    confidence: matched.length > 0 ? 'medium' : 'low',
    next_step: 'Use assess_healthcare_applicability and get_healthcare_threats with the resulting categories.',
    ...responseMeta(),
  };
}
