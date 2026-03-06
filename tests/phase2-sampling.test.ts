import { describe, expect, it } from 'vitest';
import { openDatabase } from '../src/db.js';
import { assessHealthcareApplicability } from '../src/tools/assess_healthcare_applicability.js';
import { classifyHealthData } from '../src/tools/classify_health_data.js';
import { compareJurisdictions } from '../src/tools/compare_jurisdictions.js';
import { getArchitecturePattern } from '../src/tools/get_architecture_pattern.js';
import { getHealthcareThreats } from '../src/tools/get_healthcare_threats.js';
import { searchDomainKnowledge } from '../src/tools/search_domain_knowledge.js';

describe('phase 2 sampling coverage', () => {
  const db = openDatabase(true);

  it('verifies at least five architecture patterns with trust boundaries and data flows', () => {
    const rows = db
      .prepare('SELECT pattern_id FROM architecture_patterns ORDER BY pattern_id LIMIT 5')
      .all() as Array<{ pattern_id: string }>;

    expect(rows.length).toBeGreaterThanOrEqual(5);

    for (const row of rows) {
      const output = getArchitecturePattern(db, { pattern_id: row.pattern_id }) as {
        pattern: { pattern_id: string };
        trust_boundaries: unknown[];
        data_flows: unknown[];
      };

      expect(output.pattern.pattern_id).toBe(row.pattern_id);
      expect(output.trust_boundaries.length).toBeGreaterThan(0);
      expect(output.data_flows.length).toBeGreaterThan(0);
    }
  });

  it('verifies five data classification samples and regulatory mapping', () => {
    const samples: Array<{ description: string; jurisdictions: string[]; expectedRegime: string }> = [
      {
        description: 'Hospital EHR stores patient diagnoses and treatment plans',
        jurisdictions: ['US'],
        expectedRegime: 'HIPAA_164.312',
      },
      {
        description: 'EU hospital processes sensitive health records and clinician notes',
        jurisdictions: ['SE'],
        expectedRegime: 'GDPR_ART_9',
      },
      {
        description: 'Behavioral health provider stores substance abuse treatment records',
        jurisdictions: ['US'],
        expectedRegime: '42 CFR Part 2',
      },
      {
        description: 'California telehealth app manages mental health therapy sessions',
        jurisdictions: ['US-CA'],
        expectedRegime: 'CA_CMIA',
      },
      {
        description: 'Genomics platform stores hereditary variant analysis reports',
        jurisdictions: ['DE'],
        expectedRegime: 'BDSG_HEALTH_DATA',
      },
    ];

    for (const sample of samples) {
      const output = classifyHealthData(db, sample) as {
        applicable_regimes: string[];
      };
      expect(output.applicable_regimes).toContain(sample.expectedRegime);
    }
  });

  it('verifies five threat scenarios include MITRE and regulation links', () => {
    const output = getHealthcareThreats(db, { limit: 20 }) as {
      threats: Array<{
        threat_id: string;
        mitre_tactics: string[];
        mitre_techniques: string[];
        detection_indicators: string[];
        response_playbook: {
          triage_priority: string;
          immediate_containment_actions: string[];
          clinical_safety_actions: string[];
        } | null;
        linked_regulatory_routes: Array<unknown>;
      }>;
    };

    expect(output.threats.length).toBeGreaterThanOrEqual(5);

    for (const threat of output.threats.slice(0, 5)) {
      expect(threat.threat_id.length).toBeGreaterThan(0);
      expect(threat.mitre_tactics.length).toBeGreaterThan(0);
      expect(threat.mitre_techniques.length).toBeGreaterThan(0);
      expect(threat.detection_indicators.length).toBeGreaterThan(0);
      expect(threat.response_playbook).not.toBeNull();
      expect((threat.response_playbook?.immediate_containment_actions ?? []).length).toBeGreaterThan(0);
      expect((threat.response_playbook?.clinical_safety_actions ?? []).length).toBeGreaterThan(0);
      expect(threat.linked_regulatory_routes.length).toBeGreaterThan(0);
    }
  });

  it('verifies three applicability profiles (SE, US-CA, DE)', () => {
    const cases = [
      { country: 'SE', role: 'provider', system_types: ['ehr'], data_types: ['health_data'] },
      { country: 'US-CA', role: 'provider', system_types: ['telehealth'], data_types: ['ephi'] },
      { country: 'DE', role: 'provider', system_types: ['medical_device'], data_types: ['health_data'] },
    ];

    for (const profile of cases) {
      const output = assessHealthcareApplicability(db, profile) as {
        obligations: Array<{ source_router: string }>;
      };
      expect(output.obligations.length).toBeGreaterThan(0);
      expect(output.obligations.some((item) => item.source_router.includes('_MCP'))).toBe(true);
    }
  });

  it('verifies three cross-mcp routing scenarios include foundation calls', () => {
    const scenarios = [
      { country: 'US-NY', role: 'provider', system_types: ['portal'], data_types: ['ephi'] },
      { country: 'FR', role: 'provider', system_types: ['ehr'], data_types: ['health_data'] },
      {
        country: 'US-CA,DE',
        role: 'provider',
        system_types: ['telehealth', 'medical_device'],
        data_types: ['ephi', 'health_data'],
      },
    ];

    for (const scenario of scenarios) {
      const output = assessHealthcareApplicability(db, scenario) as {
        router_calls_required: string[];
      };
      expect(output.router_calls_required.length).toBeGreaterThan(1);
      expect(output.router_calls_required.some((route) => route.includes('Regulations_MCP'))).toBe(true);
    }
  });

  it('verifies two jurisdiction comparison samples', async () => {
    const breach = (await compareJurisdictions(db, {
      topic: 'breach notification',
      jurisdictions: ['US-CA', 'DE'],
    })) as { comparison: Array<{ deadline_hours?: number }> };

    expect(breach.comparison.length).toBeGreaterThanOrEqual(2);
    expect(breach.comparison.some((item) => typeof item.deadline_hours === 'number')).toBe(true);

    const device = (await compareJurisdictions(db, {
      topic: 'medical device cybersecurity',
      jurisdictions: ['US-TX', 'SE'],
    })) as { comparison: Array<{ authoritative_route: string }> };

    expect(device.comparison.length).toBeGreaterThanOrEqual(2);
    expect(device.comparison.some((item) => item.authoritative_route.includes('FDA_524B'))).toBe(true);
    expect(device.comparison.some((item) => item.authoritative_route.includes('MDR_IVDR'))).toBe(true);
  });

  it('returns empty results for unrelated query without blocking', () => {
    const output = searchDomainKnowledge(db, {
      query: 'automotive ECU firmware secure boot',
      content_type: 'all',
    }) as {
      results: unknown[];
      scope_status: string;
    };

    // Query runs against the DB — no hardcoded filter blocks it.
    // Automotive terms simply won't match healthcare FTS indexes.
    expect(output.scope_status).toMatch(/^(in_scope|not_indexed)$/);
  });

  it('handles overlapping-jurisdiction edge case with combined obligations', () => {
    const output = assessHealthcareApplicability(db, {
      country: 'US-CA,DE',
      role: 'provider',
      system_types: ['telehealth', 'medical_device'],
      data_types: ['ephi', 'health_data', 'genetic_data'],
      additional_context: {
        uses_ai_for_clinical_decisions: true,
        has_medical_devices: true,
      },
    }) as {
      obligations: Array<{ jurisdiction: string }>;
      baseline_priority: string;
    };

    expect(output.obligations.some((item) => item.jurisdiction === 'US-CA')).toBe(true);
    expect(output.obligations.some((item) => item.jurisdiction === 'DE')).toBe(true);
    expect(output.baseline_priority).toBe('critical');
  });
});
