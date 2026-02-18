import type { SqlDatabase } from '../db.js';
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
  db: SqlDatabase,
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
      mappedIds.add('iec_81001_5_1');
      mappedIds.add('aami_sw96');
    }
    if (normalizedInputId.includes('risk')) {
      mappedIds.add('iso_14971');
    }
    if (normalizedInputId.includes('network') || normalizedInputId.includes('iot')) {
      mappedIds.add('iec_80001_1');
      mappedIds.add('ieee_11073_sdc');
      mappedIds.add('nistir_8259');
    }
    if (normalizedInputId.includes('device')) {
      mappedIds.add('aami_sw96');
      mappedIds.add('imdrf_n60');
    }
    if (normalizedInputId.includes('sbom') || normalizedInputId.includes('component_inventory')) {
      mappedIds.add('spdx');
      mappedIds.add('cyclonedx');
    }
    if (
      normalizedInputId.includes('vuln') ||
      normalizedInputId.includes('advisory') ||
      normalizedInputId.includes('disclosure')
    ) {
      mappedIds.add('iso_29147');
      mappedIds.add('iso_30111');
      mappedIds.add('csaf_2_0');
      mappedIds.add('vex');
    }
    if (
      normalizedInputId.includes('supply_chain') ||
      normalizedInputId.includes('supplier') ||
      normalizedInputId.includes('third_party')
    ) {
      mappedIds.add('csaf_2_0');
      mappedIds.add('vex');
      mappedIds.add('spdx');
      mappedIds.add('cyclonedx');
    }
    if (normalizedInputId.includes('ransomware') || normalizedInputId.includes('downtime')) {
      mappedIds.add('hhs_405d_hicp');
    }
  }

  if (caseInsensitiveMappings.length === 0 && input.input_type === 'requirement') {
    if (normalizedInputId.includes('smart') || normalizedInputId.includes('fhir')) {
      mappedIds.add('hl7_fhir_r4');
      mappedIds.add('hl7_fhir_r5');
      mappedIds.add('smart_on_fhir');
      mappedIds.add('ihe_iua');
    }
    if (normalizedInputId.includes('smart') && normalizedInputId.includes('backend')) {
      mappedIds.add('smart_backend_services');
    }
    if (normalizedInputId.includes('bulk') && normalizedInputId.includes('fhir')) {
      mappedIds.add('fhir_bulk_data');
    }
    if (normalizedInputId.includes('dicom') || normalizedInputId.includes('imaging')) {
      mappedIds.add('dicom');
      mappedIds.add('ihe_atna');
    }
    if (normalizedInputId.includes('dicomweb')) {
      mappedIds.add('dicomweb');
    }
    if (normalizedInputId.includes('xds')) {
      mappedIds.add('ihe_xds');
    }
    if (normalizedInputId.includes('mhd')) {
      mappedIds.add('ihe_mhd');
    }
    if (normalizedInputId.includes('xca')) {
      mappedIds.add('ihe_xca');
    }
    if (normalizedInputId.includes('xcpd')) {
      mappedIds.add('ihe_xcpd');
    }
    if (normalizedInputId.includes('pixm') || normalizedInputId.includes('pix')) {
      mappedIds.add('ihe_pixm');
    }
    if (normalizedInputId.includes('pdqm') || normalizedInputId.includes('pdq')) {
      mappedIds.add('ihe_pdqm');
    }
    if (normalizedInputId.includes('openehr')) {
      mappedIds.add('openehr');
    }
    if (normalizedInputId.includes('udap')) {
      mappedIds.add('udap');
      mappedIds.add('smart_on_fhir');
    }
    if (normalizedInputId.includes('cda') || normalizedInputId.includes('ccda')) {
      mappedIds.add('hl7_cda_ccda');
      mappedIds.add('direct_project');
    }
    if (normalizedInputId.includes('hl7v2') || normalizedInputId.includes('hl7_v2')) {
      mappedIds.add('hl7_v2');
    }
    if (
      normalizedInputId.includes('x12') ||
      normalizedInputId.includes('837') ||
      normalizedInputId.includes('835') ||
      normalizedInputId.includes('edi')
    ) {
      mappedIds.add('x12_005010');
    }
    if (
      normalizedInputId.includes('ncpdp') ||
      normalizedInputId.includes('script') ||
      normalizedInputId.includes('eprescrib')
    ) {
      mappedIds.add('ncpdp_script');
    }
    if (normalizedInputId.includes('sbom')) {
      mappedIds.add('spdx');
      mappedIds.add('cyclonedx');
    }
    if (normalizedInputId.includes('vex')) {
      mappedIds.add('vex');
    }
    if (normalizedInputId.includes('csaf') || normalizedInputId.includes('advisory')) {
      mappedIds.add('csaf_2_0');
    }
    if (normalizedInputId.includes('hipaa')) {
      mappedIds.add('nist_sp_800_66');
    }
    if (normalizedInputId.includes('ehds')) {
      mappedIds.add('hl7_ips');
      mappedIds.add('ihe_xds');
      mappedIds.add('ihe_xca');
      mappedIds.add('ihe_mhd');
    }
    if (normalizedInputId.includes('tefca') || normalizedInputId.includes('qhin')) {
      mappedIds.add('tefca_qtf');
      mappedIds.add('ihe_xca');
      mappedIds.add('ihe_xcpd');
      mappedIds.add('udap');
    }
    if (normalizedInputId.includes('hicp') || normalizedInputId.includes('405d')) {
      mappedIds.add('hhs_405d_hicp');
    }
    if (normalizedInputId.includes('fda') || normalizedInputId.includes('524b')) {
      mappedIds.add('fda_premarket_cyber_2023');
      mappedIds.add('imdrf_n60');
      mappedIds.add('aami_sw96');
      mappedIds.add('spdx');
      mappedIds.add('cyclonedx');
      mappedIds.add('vex');
      mappedIds.add('iso_30111');
    }
    if (normalizedInputId.includes('imdrf')) {
      mappedIds.add('imdrf_n60');
    }
    if (normalizedInputId.includes('sw96')) {
      mappedIds.add('aami_sw96');
    }
    if (normalizedInputId.includes('supply_chain') || normalizedInputId.includes('supplier')) {
      mappedIds.add('csaf_2_0');
      mappedIds.add('vex');
    }
    if (normalizedInputId.includes('ai_act') || normalizedInputId.includes('clinical_ai')) {
      mappedIds.add('iso_14971');
      mappedIds.add('iec_62304');
      mappedIds.add('iec_81001_5_1');
    }
  }

  if (caseInsensitiveMappings.length === 0 && input.input_type === 'architecture_pattern') {
    if (normalizedInputId.includes('ehr') || normalizedInputId.includes('fhir')) {
      mappedIds.add('hl7_fhir_r4');
      mappedIds.add('hl7_fhir_r5');
      mappedIds.add('smart_on_fhir');
      mappedIds.add('fhir_bulk_data');
    }
    if (normalizedInputId.includes('hie') || normalizedInputId.includes('exchange')) {
      mappedIds.add('ihe_xua');
      mappedIds.add('ihe_iua');
      mappedIds.add('hl7_ips');
      mappedIds.add('ihe_xds');
      mappedIds.add('ihe_xca');
      mappedIds.add('ihe_xcpd');
      mappedIds.add('ihe_pixm');
      mappedIds.add('ihe_pdqm');
      mappedIds.add('ihe_mhd');
      mappedIds.add('tefca_qtf');
      mappedIds.add('iso_22600');
      mappedIds.add('direct_project');
      mappedIds.add('udap');
    }
    if (normalizedInputId.includes('iomt') || normalizedInputId.includes('device')) {
      mappedIds.add('iec_80001_1');
      mappedIds.add('ieee_11073_sdc');
      mappedIds.add('ieee_11073_phd');
      mappedIds.add('ihe_pcd');
      mappedIds.add('nistir_8259');
    }
    if (
      normalizedInputId.includes('samd') ||
      normalizedInputId.includes('clinical_ai') ||
      normalizedInputId.includes('ai')
    ) {
      mappedIds.add('iec_62304');
      mappedIds.add('iso_14971');
      mappedIds.add('iec_81001_5_1');
      mappedIds.add('iec_82304_1');
      mappedIds.add('aami_sw96');
      mappedIds.add('imdrf_n60');
    }
    if (
      normalizedInputId.includes('pacs') ||
      normalizedInputId.includes('dicom') ||
      normalizedInputId.includes('imaging')
    ) {
      mappedIds.add('dicom');
      mappedIds.add('dicomweb');
      mappedIds.add('ihe_atna');
    }
    if (normalizedInputId.includes('pharmacy') || normalizedInputId.includes('medication')) {
      mappedIds.add('ncpdp_script');
      mappedIds.add('hl7_fhir_r4');
    }
    if (normalizedInputId.includes('telehealth') || normalizedInputId.includes('remote_monitoring')) {
      mappedIds.add('smart_on_fhir');
      mappedIds.add('ieee_11073_phd');
      mappedIds.add('ihe_pcd');
    }
    if (normalizedInputId.includes('erp') || normalizedInputId.includes('claims')) {
      mappedIds.add('x12_005010');
    }
    if (normalizedInputId.includes('openehr')) {
      mappedIds.add('openehr');
    }
    if (normalizedInputId.includes('cda') || normalizedInputId.includes('ccda')) {
      mappedIds.add('hl7_cda_ccda');
      mappedIds.add('direct_project');
    }
  }

  if (caseInsensitiveMappings.length === 0 && input.input_type === 'threat') {
    if (normalizedInputId.includes('token') || normalizedInputId.includes('fhir')) {
      mappedIds.add('smart_on_fhir');
      mappedIds.add('ihe_iua');
      mappedIds.add('hl7_fhir_r4');
    }
    if (normalizedInputId.includes('dicom') || normalizedInputId.includes('imaging')) {
      mappedIds.add('dicom');
      mappedIds.add('dicomweb');
      mappedIds.add('ihe_atna');
    }
    if (normalizedInputId.includes('iomt') || normalizedInputId.includes('ransomware')) {
      mappedIds.add('iec_80001_1');
      mappedIds.add('ieee_11073_sdc');
      mappedIds.add('ihe_pcd');
      mappedIds.add('nistir_8259');
      mappedIds.add('hhs_405d_hicp');
    }
    if (
      normalizedInputId.includes('firmware') ||
      normalizedInputId.includes('supply_chain') ||
      normalizedInputId.includes('device')
    ) {
      mappedIds.add('iso_14971');
      mappedIds.add('iec_62304');
      mappedIds.add('iec_81001_5_1');
      mappedIds.add('aami_sw96');
      mappedIds.add('imdrf_n60');
      mappedIds.add('aami_tir57');
      mappedIds.add('aami_tir97');
      mappedIds.add('spdx');
      mappedIds.add('cyclonedx');
      mappedIds.add('csaf_2_0');
      mappedIds.add('vex');
      mappedIds.add('iso_29147');
      mappedIds.add('iso_30111');
    }
    if (
      normalizedInputId.includes('prescription') ||
      normalizedInputId.includes('refill') ||
      normalizedInputId.includes('ncpdp')
    ) {
      mappedIds.add('ncpdp_script');
    }
    if (normalizedInputId.includes('claims') || normalizedInputId.includes('x12')) {
      mappedIds.add('x12_005010');
    }
    if (normalizedInputId.includes('remote_monitoring') || normalizedInputId.includes('telemetry')) {
      mappedIds.add('ieee_11073_phd');
      mappedIds.add('ihe_pcd');
      mappedIds.add('nistir_8259');
    }
    if (normalizedInputId.includes('xds') || normalizedInputId.includes('registry')) {
      mappedIds.add('ihe_xds');
      mappedIds.add('ihe_xca');
      mappedIds.add('ihe_atna');
    }
    if (
      normalizedInputId.includes('xcpd') ||
      normalizedInputId.includes('identity_mismatch') ||
      normalizedInputId.includes('patient_match')
    ) {
      mappedIds.add('ihe_xcpd');
      mappedIds.add('ihe_pixm');
      mappedIds.add('ihe_pdqm');
      mappedIds.add('tefca_qtf');
      mappedIds.add('iso_22600');
    }
    if (
      normalizedInputId.includes('openehr') ||
      normalizedInputId.includes('archetype') ||
      normalizedInputId.includes('template')
    ) {
      mappedIds.add('openehr');
      mappedIds.add('iso_27799');
    }
    if (
      normalizedInputId.includes('udap') ||
      normalizedInputId.includes('dynamic_client') ||
      normalizedInputId.includes('registration')
    ) {
      mappedIds.add('udap');
      mappedIds.add('smart_on_fhir');
      mappedIds.add('smart_backend_services');
    }
    if (
      normalizedInputId.includes('ccda') ||
      normalizedInputId.includes('cda') ||
      normalizedInputId.includes('document_injection')
    ) {
      mappedIds.add('hl7_cda_ccda');
      mappedIds.add('direct_project');
    }
    if (
      normalizedInputId.includes('terminology') ||
      normalizedInputId.includes('coding') ||
      normalizedInputId.includes('concept_map')
    ) {
      mappedIds.add('snomed_ct');
      mappedIds.add('loinc');
      mappedIds.add('icd_10_11');
      mappedIds.add('iso_27799');
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
