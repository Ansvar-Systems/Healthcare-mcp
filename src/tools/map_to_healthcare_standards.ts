import type Database from 'better-sqlite3';
import type { MapToHealthcareStandardsInput, ToolError } from '../types.js';

type MappingRow = {
  mapping_id: string;
  input_type: string;
  input_id: string;
  standard_id: string;
  mapping_type: string;
  rationale: string;
};

type StandardRow = {
  standard_id: string;
  name: string;
  authority: string;
  scope: string;
  version: string | null;
  status: string;
};

export function mapToHealthcareStandards(
  db: Database.Database,
  args: unknown,
): Record<string, unknown> | ToolError {
  const raw = args as MapToHealthcareStandardsInput & {
    requirement_ref?: string;
    control_id?: string;
  };
  const input: MapToHealthcareStandardsInput = raw.input_type && raw.input_id
    ? raw
    : raw.control_id
      ? { input_type: 'control', input_id: raw.control_id }
      : raw.requirement_ref
        ? { input_type: 'requirement', input_id: raw.requirement_ref }
        : (raw as MapToHealthcareStandardsInput);

  if (!input?.input_type || !input?.input_id) {
    return {
      error: 'input_type and input_id are required',
      hint: 'Example: {"input_type":"threat","input_id":"th_hl7_fhir_token_theft"}',
    };
  }

  const directMappings = db
    .prepare(
      `SELECT mapping_id, input_type, input_id, standard_id, mapping_type, rationale
       FROM standard_mappings
       WHERE input_type = ? AND input_id = ?
       ORDER BY mapping_id`,
    )
    .all(input.input_type, input.input_id) as MappingRow[];

  const caseInsensitiveMappings =
    directMappings.length > 0
      ? directMappings
      : (db
          .prepare(
            `SELECT mapping_id, input_type, input_id, standard_id, mapping_type, rationale
             FROM standard_mappings
             WHERE input_type = ? AND lower(input_id) = lower(?)
             ORDER BY mapping_id`,
          )
          .all(input.input_type, input.input_id) as MappingRow[]);

  const mappedIds = new Set(caseInsensitiveMappings.map((row) => row.standard_id));
  const normalizedInputId = input.input_id.toLowerCase();

  if (caseInsensitiveMappings.length === 0 && input.input_type === 'control') {
    if (normalizedInputId.includes('sdlc') || normalizedInputId.includes('dev')) {
      mappedIds.add('iec_62304');
    }
    if (normalizedInputId.includes('risk')) {
      mappedIds.add('iso_14971');
    }
    if (normalizedInputId.includes('network') || normalizedInputId.includes('iot')) {
      mappedIds.add('iec_80001_1');
    }
  }

  if (caseInsensitiveMappings.length === 0 && input.input_type === 'requirement') {
    if (normalizedInputId.includes('smart') || normalizedInputId.includes('fhir')) {
      mappedIds.add('hl7_fhir_r4');
      mappedIds.add('hl7_fhir_r5');
      mappedIds.add('smart_on_fhir');
      mappedIds.add('ihe_iua');
    }
    if (normalizedInputId.includes('dicom') || normalizedInputId.includes('imaging')) {
      mappedIds.add('dicom');
      mappedIds.add('ihe_atna');
    }
    if (normalizedInputId.includes('hl7v2') || normalizedInputId.includes('hl7_v2')) {
      mappedIds.add('hl7_v2');
    }
    if (normalizedInputId.includes('hipaa')) {
      mappedIds.add('nist_sp_800_66');
    }
  }

  const standards = [...mappedIds].map((id) =>
    db
      .prepare(
        'SELECT standard_id, name, authority, scope, version, status FROM technical_standards WHERE standard_id = ?',
      )
      .get(id) as StandardRow | undefined,
  ).filter((row): row is StandardRow => Boolean(row));

  return {
    input,
    mappings: caseInsensitiveMappings,
    standards,
    coverage: {
      direct_mapping_count: caseInsensitiveMappings.length,
      standard_count: standards.length,
      inference_used: caseInsensitiveMappings.length === 0 && standards.length > 0,
    },
    composition_note:
      'Use this output with Security Controls MCP mappings to create control implementation specifications per standard.',
  };
}
