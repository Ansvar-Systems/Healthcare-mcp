import { describe, expect, it } from 'vitest';
import { openDatabase } from '../src/db.js';
import { assessHealthcareApplicability } from '../src/tools/assess_healthcare_applicability.js';

type Obligation = {
  regulation_refs?: string[];
};

function collectRegulationRefs(obligations: Obligation[]): Set<string> {
  const refs = new Set<string>();
  for (const obligation of obligations) {
    for (const ref of obligation.regulation_refs ?? []) {
      refs.add(ref);
    }
  }
  return refs;
}

describe('jurisdiction overlay applicability pack', () => {
  const db = openDatabase(true);

  it('covers SE EHR health-data scenario with GDPR, NIS2, and Patientdatalagen', () => {
    const output = assessHealthcareApplicability(db, {
      country: 'SE',
      role: 'provider',
      system_types: ['ehr'],
      data_types: ['health_data'],
      additional_context: {
        uses_ai_for_clinical_decisions: false,
      },
    }) as { obligations: Obligation[] };

    const refs = collectRegulationRefs(output.obligations);
    expect(refs.has('GDPR_ART_9')).toBe(true);
    expect(refs.has('NIS2_ART_21')).toBe(true);
    expect(refs.has('SE_PATIENTDATALAGEN')).toBe(true);
  });

  it('covers US-CA telehealth AI scenario with HIPAA, CMIA, CCPA, FDA SaMD, and telehealth law', () => {
    const output = assessHealthcareApplicability(db, {
      country: 'US-CA',
      role: 'provider',
      system_types: ['telehealth'],
      data_types: ['ephi', 'mental_health'],
      additional_context: {
        uses_ai_for_clinical_decisions: true,
      },
    }) as { obligations: Obligation[] };

    const refs = collectRegulationRefs(output.obligations);
    expect(refs.has('HIPAA_164.312')).toBe(true);
    expect(refs.has('CA_CMIA')).toBe(true);
    expect(refs.has('CCPA_1798.100')).toBe(true);
    expect(refs.has('FDA_524B')).toBe(true);
    expect(refs.has('CA_TELEHEALTH_LAW')).toBe(true);
  });

  it('covers DE medical-device AI scenario with MDR, GDPR, BDSG, AI Act, and NIS2', () => {
    const output = assessHealthcareApplicability(db, {
      country: 'DE',
      role: 'provider',
      system_types: ['medical_device'],
      data_types: ['health_data', 'genetic_data'],
      additional_context: {
        uses_ai_for_clinical_decisions: true,
      },
    }) as { obligations: Obligation[] };

    const refs = collectRegulationRefs(output.obligations);
    expect(refs.has('MDR_ANNEX_I')).toBe(true);
    expect(refs.has('GDPR_ART_9')).toBe(true);
    expect(refs.has('BDSG_HEALTH_DATA')).toBe(true);
    expect(refs.has('AI_ACT_ANNEX_III_HEALTH')).toBe(true);
    expect(refs.has('NIS2_ART_21')).toBe(true);
  });
});
