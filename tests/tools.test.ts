import { describe, expect, it } from 'vitest';
import { openDatabase } from '../src/db.js';
import { classifyHealthData } from '../src/tools/classify_health_data.js';
import { getArchitecturePattern } from '../src/tools/get_architecture_pattern.js';
import { getHealthcareThreats } from '../src/tools/get_healthcare_threats.js';
import { assessBreachObligations } from '../src/tools/assess_breach_obligations.js';

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
});
