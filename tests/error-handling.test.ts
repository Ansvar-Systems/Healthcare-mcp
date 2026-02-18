import { describe, expect, it } from 'vitest';
import { openDatabase } from '../src/db.js';
import { assessBreachObligations } from '../src/tools/assess_breach_obligations.js';
import { assessHealthcareApplicability } from '../src/tools/assess_healthcare_applicability.js';
import { classifyHealthData } from '../src/tools/classify_health_data.js';
import { compareJurisdictions } from '../src/tools/compare_jurisdictions.js';
import { getHealthcareThreats } from '../src/tools/get_healthcare_threats.js';
import { getThreatResponsePlaybook } from '../src/tools/get_threat_response_playbook.js';
import { mapToHealthcareStandards } from '../src/tools/map_to_healthcare_standards.js';
import { resolveAuthoritativeContext } from '../src/tools/resolve_authoritative_context.js';
import { searchDomainKnowledge } from '../src/tools/search_domain_knowledge.js';

describe('error handling robustness', () => {
  const db = openDatabase(true);

  it('returns actionable validation errors for malformed classify_data input', () => {
    const result = classifyHealthData(db, { description: 'short' }) as { error?: string; hint?: string };
    expect(typeof result.error).toBe('string');
    expect(typeof result.hint).toBe('string');
  });

  it('sanitizes invalid threat search query and returns guidance', () => {
    const result = getHealthcareThreats(db, { query: '!!!@@@###' }) as { error?: string; hint?: string };
    expect(typeof result.error).toBe('string');
    expect(typeof result.hint).toBe('string');
  });

  it('returns clear error for incomplete breach obligation input', () => {
    const result = assessBreachObligations(db, {
      jurisdictions: ['US'],
      incident_summary: 'test incident',
    }) as { error?: string; hint?: string };
    expect(typeof result.error).toBe('string');
    expect(typeof result.hint).toBe('string');
  });

  it('returns clear error for malformed applicability profile content', () => {
    const result = assessHealthcareApplicability(db, {
      organization_profile: {
        jurisdictions: 'US',
        entity_type: 'provider',
        data_categories: 'ephi',
      } as unknown as {
        jurisdictions: string[];
        entity_type: string;
        data_categories: string[];
      },
    }) as { error?: string; hint?: string };
    expect(typeof result.error).toBe('string');
    expect(typeof result.hint).toBe('string');
  });

  it('returns clear error when standards mapping input is missing', () => {
    const result = mapToHealthcareStandards(db, {}) as { error?: string; hint?: string };
    expect(typeof result.error).toBe('string');
    expect(typeof result.hint).toBe('string');
  });

  it('returns clear error for invalid jurisdiction compare call', async () => {
    const result = (await compareJurisdictions(db, { topic: '' })) as { error?: string; hint?: string };
    expect(typeof result.error).toBe('string');
    expect(typeof result.hint).toBe('string');
  });

  it('returns clear error for invalid authoritative context request', async () => {
    const result = (await resolveAuthoritativeContext(db, { topic: 'ab' })) as {
      error?: string;
      hint?: string;
    };
    expect(typeof result.error).toBe('string');
    expect(typeof result.hint).toBe('string');
  });

  it('returns clear error for invalid domain search query', () => {
    const result = searchDomainKnowledge(db, { query: ' ' }) as { error?: string; hint?: string };
    expect(typeof result.error).toBe('string');
    expect(typeof result.hint).toBe('string');
  });

  it('returns clear error for missing threat response playbook id', () => {
    const result = getThreatResponsePlaybook(db, {}) as { error?: string; hint?: string };
    expect(typeof result.error).toBe('string');
    expect(typeof result.hint).toBe('string');
  });
});
