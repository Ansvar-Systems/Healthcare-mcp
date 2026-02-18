import { describe, expect, it } from 'vitest';
import { openDatabase } from '../src/db.js';
import { getProtocolSecurity } from '../src/tools/get_protocol_security.js';

describe('standards governance integrity', () => {
  const db = openDatabase(true);

  it('keeps the expanded healthcare standards corpus with full mapping coverage', () => {
    const counts = db
      .prepare(
        `SELECT
           (SELECT COUNT(*) FROM technical_standards) as standard_count,
           (SELECT COALESCE(COUNT(*), 0)
              FROM (
                SELECT s.standard_id
                FROM technical_standards s
                LEFT JOIN standard_mappings m ON m.standard_id = s.standard_id
                GROUP BY s.standard_id
                HAVING COUNT(m.mapping_id) = 0
              )) as unmapped_count`,
      )
      .get() as { standard_count: number; unmapped_count: number };

    expect(counts.standard_count).toBeGreaterThanOrEqual(53);
    expect(counts.unmapped_count).toBe(0);
  });

  it('supports protocol-security profiles for the full advanced interoperability set', () => {
    const protocols = [
      'HL7v2',
      'FHIR_R4',
      'FHIR_R5',
      'SMART_ON_FHIR',
      'SMART_BACKEND_SERVICES',
      'FHIR_BULK_DATA',
      'DICOM',
      'DICOMWEB',
      'ATNA',
      'XUA',
      'IUA',
      'SeR',
      'XDS',
      'MHD',
      'XCA',
      'XCPD',
      'PIXm',
      'PDQm',
      'IHE_PCD',
      'openEHR',
      'UDAP',
      'C-CDA',
      'DIRECT_PROJECT',
      'IEEE_11073_SDC',
      'IEEE_11073_PHD',
      'X12_005010',
      'NCPDP_SCRIPT',
      'SPDX',
      'CYCLONEDX',
      'CSAF_2_0',
      'VEX',
    ];

    for (const protocol of protocols) {
      const output = getProtocolSecurity({ protocol }) as {
        error?: string;
        recommended_controls?: string[];
      };

      expect(output.error, `unsupported protocol profile: ${protocol}`).toBeUndefined();
      expect((output.recommended_controls ?? []).length, `missing controls for protocol: ${protocol}`).toBeGreaterThan(
        0,
      );
    }
  });

  it('includes advanced healthcare governance standards with active mapping coverage', () => {
    const expected = ['tefca_qtf', 'hhs_405d_hicp', 'imdrf_n60', 'aami_sw96', 'nistir_8259'];
    const rows = db
      .prepare(
        `SELECT
           s.standard_id as standard_id,
           (SELECT COUNT(*) FROM standard_mappings m WHERE m.standard_id = s.standard_id) as mapping_count
         FROM technical_standards s
         WHERE s.standard_id IN (${expected.map(() => '?').join(', ')})
         ORDER BY s.standard_id`,
      )
      .all(...expected) as Array<{ standard_id: string; mapping_count: number }>;

    expect(rows.length).toBe(expected.length);
    for (const row of rows) {
      expect(row.mapping_count, `${row.standard_id} should have at least one mapping`).toBeGreaterThan(0);
    }
  });

  it('keeps every standard mapped by at least two crosswalk entries for resilience', () => {
    const counts = db
      .prepare(
        `SELECT COALESCE(COUNT(*), 0) as low_coverage_count
         FROM (
           SELECT s.standard_id
           FROM technical_standards s
           LEFT JOIN standard_mappings m ON m.standard_id = s.standard_id
           GROUP BY s.standard_id
           HAVING COUNT(m.mapping_id) <= 1
         )`,
      )
      .get() as { low_coverage_count: number };

    expect(counts.low_coverage_count).toBe(0);
  });
});
