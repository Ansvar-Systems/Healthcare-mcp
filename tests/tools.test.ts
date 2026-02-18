import { describe, expect, it } from 'vitest';
import { openDatabase } from '../src/db.js';
import { classifyHealthData } from '../src/tools/classify_health_data.js';
import { getArchitecturePattern } from '../src/tools/get_architecture_pattern.js';
import { getHealthcareThreats } from '../src/tools/get_healthcare_threats.js';
import { assessBreachObligations } from '../src/tools/assess_breach_obligations.js';
import { searchDomainKnowledge } from '../src/tools/search_domain_knowledge.js';
import { assessHealthcareApplicability } from '../src/tools/assess_healthcare_applicability.js';

describe('healthcare tool scaffold', () => {
  const db = openDatabase(true);

  it('classifies health data into critical tier', () => {
    const output = classifyHealthData(db, {
      description: 'Patient diagnosis and genomic dataset with treatment history',
      jurisdictions: ['US', 'EU'],
    }) as { protection_tier: string };

    expect(output.protection_tier).toBe('critical');
  });

  it('returns architecture pattern details', () => {
    const output = getArchitecturePattern(db, { pattern_id: 'ehr_fhir_gateway' }) as {
      pattern: { pattern_id: string };
      trust_boundaries: Array<unknown>;
    };

    expect(output.pattern.pattern_id).toBe('ehr_fhir_gateway');
    expect(output.trust_boundaries.length).toBeGreaterThan(0);
  });

  it('returns healthcare threats for a pattern', () => {
    const output = getHealthcareThreats(db, {
      pattern_id: 'ehr_fhir_gateway',
      limit: 10,
    }) as {
      threats: Array<{
        threat_id: string;
        mitre_techniques: string[];
        response_playbook: { triage_priority: string } | null;
      }>;
    };

    expect(output.threats.length).toBeGreaterThan(0);
    expect(output.threats.some((threat) => threat.threat_id === 'th_hl7_fhir_token_theft')).toBe(true);
    expect(output.threats.some((threat) => threat.mitre_techniques.length > 0)).toBe(true);
    expect(output.threats.some((threat) => threat.response_playbook?.triage_priority === 'P1')).toBe(true);
  });

  it('computes breach obligations with strictest deadline', () => {
    const output = assessBreachObligations(db, {
      jurisdictions: ['US', 'EU'],
      data_categories: ['ephi'],
      incident_summary: 'Suspected unauthorized export of patient records',
    }) as { strictest_deadline: { deadline_hours: number } };

    expect(output.strictest_deadline.deadline_hours).toBe(24);
  });

  it('supports detail-level and cursor pagination for threat results', () => {
    const firstPage = getHealthcareThreats(db, {
      query: 'ransomware',
      detail_level: 'summary',
      limit: 1,
    }) as {
      threats: Array<{ threat_id: string; name: string }>;
      pagination: { next_cursor: string | null };
      scope_status: string;
    };

    expect(firstPage.scope_status).toBe('in_scope');
    expect(firstPage.threats.length).toBe(1);

    if (firstPage.pagination.next_cursor) {
      const secondPage = getHealthcareThreats(db, {
        query: 'ransomware',
        detail_level: 'summary',
        limit: 1,
        cursor: firstPage.pagination.next_cursor,
      }) as {
        threats: Array<{ threat_id: string }>;
      };

      expect(secondPage.threats.length).toBeLessThanOrEqual(1);
    }
  });

  it('returns scope status and cursor pagination for domain search', () => {
    const firstPage = searchDomainKnowledge(db, {
      query: 'FHIR',
      content_type: 'all',
      limit: 2,
    }) as {
      scope_status: string;
      results: unknown[];
      pagination: { next_cursor: string | null };
    };

    expect(firstPage.scope_status).toBe('in_scope');
    expect(firstPage.results.length).toBeGreaterThan(0);
    expect(typeof firstPage.pagination.next_cursor === 'string' || firstPage.pagination.next_cursor === null).toBe(
      true,
    );
  });

  it('supports summary mode for applicability routing', () => {
    const output = assessHealthcareApplicability(db, {
      country: 'US-CA,DE',
      role: 'provider',
      system_types: ['ehr', 'medical_device'],
      data_types: ['ephi', 'health_data'],
      detail_level: 'summary',
      additional_context: {
        has_medical_devices: true,
        uses_ai_for_clinical_decisions: true,
      },
    }) as {
      scope_status: string;
      obligation_count: number;
      top_obligations: Array<unknown>;
    };

    expect(output.scope_status).toBe('in_scope');
    expect(output.obligation_count).toBeGreaterThan(0);
    expect(output.top_obligations.length).toBeGreaterThan(0);
  });
});
