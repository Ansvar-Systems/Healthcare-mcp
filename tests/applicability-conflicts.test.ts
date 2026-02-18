import { describe, expect, it } from 'vitest';
import { openDatabase } from '../src/db.js';
import { assessHealthcareApplicability } from '../src/tools/assess_healthcare_applicability.js';

describe('applicability conflict resolver', () => {
  const db = openDatabase(true);

  it('returns deterministic strictest-wins conflict decisions for overlapping obligations', () => {
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
      obligations: Array<{ obligation_id: string }>;
      conflict_resolution: {
        policy: { name: string };
        strictest_obligations: Array<{ obligation_id: string; strictness_score: number }>;
        conflicts: Array<{ selected_obligation_id: string; selected_priority: string }>;
        summary: { conflicts_detected: number };
      };
      decision_quality: {
        requires_authoritative_validation: boolean;
        abstain_from_definitive_legal_advice: boolean;
      };
    };

    expect(output.conflict_resolution.policy.name).toBe('strictest_wins');
    expect(output.conflict_resolution.summary.conflicts_detected).toBeGreaterThan(0);

    const obligationIds = new Set(output.obligations.map((item) => item.obligation_id));
    for (const conflict of output.conflict_resolution.conflicts) {
      expect(obligationIds.has(conflict.selected_obligation_id)).toBe(true);
    }

    expect(
      output.conflict_resolution.strictest_obligations.every((item) => item.strictness_score > 0),
    ).toBe(true);

    expect(
      output.conflict_resolution.conflicts.some((item) => item.selected_priority === 'critical'),
    ).toBe(true);
    expect(output.decision_quality.requires_authoritative_validation).toBe(true);
    expect(output.decision_quality.abstain_from_definitive_legal_advice).toBe(true);
  });

  it('flags authoritative validation requirement when synthesized fallback is used', () => {
    const output = assessHealthcareApplicability(db, {
      country: 'FR',
      role: 'provider',
      system_types: ['ehr'],
      data_types: ['health_data'],
    }) as {
      overlay_summary: { synthesized_country_codes: string[] };
      decision_quality: {
        requires_authoritative_validation: boolean;
        abstain_from_definitive_legal_advice: boolean;
      };
    };

    expect(output.overlay_summary.synthesized_country_codes).toContain('FR');
    expect(output.decision_quality.requires_authoritative_validation).toBe(true);
    expect(output.decision_quality.abstain_from_definitive_legal_advice).toBe(true);
  });
});
