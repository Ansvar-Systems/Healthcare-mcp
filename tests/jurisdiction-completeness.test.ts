import { describe, expect, it } from 'vitest';
import { openDatabase } from '../src/db.js';
import { EU_COUNTRY_CODES, US_STATE_CODES } from '../src/jurisdictions.js';
import { assessHealthcareApplicability } from '../src/tools/assess_healthcare_applicability.js';

describe('jurisdiction completeness', () => {
  const db = openDatabase(true);

  it('returns obligations for every EU member state under baseline healthcare provider profile', () => {
    for (const countryCode of EU_COUNTRY_CODES) {
      const output = assessHealthcareApplicability(db, {
        country: countryCode,
        role: 'provider',
        system_types: ['ehr'],
        data_types: ['health_data'],
      }) as {
        obligations: Array<unknown>;
        overlay_summary: {
          unsupported_country_codes: string[];
          out_of_scope: string[];
        };
      };

      expect(output.obligations.length).toBeGreaterThan(0);
      expect(output.overlay_summary.unsupported_country_codes.length).toBe(0);
      expect(output.overlay_summary.out_of_scope.length).toBe(0);
    }
  });

  it('returns obligations for all US states and DC under baseline healthcare provider profile', () => {
    for (const stateCode of US_STATE_CODES) {
      const output = assessHealthcareApplicability(db, {
        country: `US-${stateCode}`,
        role: 'provider',
        system_types: ['portal'],
        data_types: ['ephi'],
      }) as {
        obligations: Array<unknown>;
        overlay_summary: {
          unsupported_country_codes: string[];
          out_of_scope: string[];
        };
      };

      expect(output.obligations.length).toBeGreaterThan(0);
      expect(output.overlay_summary.unsupported_country_codes.length).toBe(0);
      expect(output.overlay_summary.out_of_scope.length).toBe(0);
    }
  });
});
