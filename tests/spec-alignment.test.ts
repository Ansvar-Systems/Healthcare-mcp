import { describe, expect, it } from 'vitest';
import { openDatabase } from '../src/db.js';
import { listProfiles } from '../src/tools/list_profiles.js';
import { listSources } from '../src/tools/list_sources.js';
import { listArchitecturePatterns } from '../src/tools/list_architecture_patterns.js';
import { searchDomainKnowledge } from '../src/tools/search_domain_knowledge.js';
import { getProtocolSecurity } from '../src/tools/get_protocol_security.js';
import { assessClinicalRisk } from '../src/tools/assess_clinical_risk.js';
import { mapHipaaSafeguards } from '../src/tools/map_hipaa_safeguards.js';
import { mapToHealthcareStandards } from '../src/tools/map_to_healthcare_standards.js';
import { getHealthcareThreats } from '../src/tools/get_healthcare_threats.js';
import { createRemediationBacklog } from '../src/tools/create_remediation_backlog.js';
import { getThreatResponsePlaybook } from '../src/tools/get_threat_response_playbook.js';

describe('spec alignment tool additions', () => {
  const db = openDatabase(true);

  it('lists sources from sources.yml', () => {
    const output = listSources(db, {}) as { source_count: number };
    expect(output.source_count).toBeGreaterThan(0);
  });

  it('lists architecture patterns', () => {
    const output = listArchitecturePatterns(db, {}) as { pattern_count: number };
    expect(output.pattern_count).toBeGreaterThan(0);
  });

  it('lists threat expert profiles with MITRE and detection coverage counts', () => {
    const output = listProfiles(db, {
      profile_type: 'threat_expert_profiles',
    }) as {
      threat_expert_profiles: Array<{
        mitre_technique_count: number;
        detection_indicator_count: number;
      }>;
    };

    expect(output.threat_expert_profiles.length).toBeGreaterThan(0);
    expect(
      output.threat_expert_profiles.every(
        (item) => item.mitre_technique_count > 0 && item.detection_indicator_count > 0,
      ),
    ).toBe(true);
  });

  it('lists threat response playbook profiles with containment and forensic coverage counts', () => {
    const output = listProfiles(db, {
      profile_type: 'threat_response_playbooks',
    }) as {
      threat_response_playbooks: Array<{
        containment_action_count: number;
        forensic_artifact_count: number;
      }>;
    };

    expect(output.threat_response_playbooks.length).toBeGreaterThan(0);
    expect(
      output.threat_response_playbooks.every(
        (item) => item.containment_action_count > 0 && item.forensic_artifact_count > 0,
      ),
    ).toBe(true);
  });

  it('searches domain knowledge across catalog data', () => {
    const output = searchDomainKnowledge(db, {
      query: 'ransomware',
      content_type: 'threat',
      limit: 5,
    }) as { results: Array<unknown> };

    expect(output.results.length).toBeGreaterThan(0);
  });

  it('returns protocol security profile', () => {
    const output = getProtocolSecurity({ protocol: 'HL7v2' }) as {
      known_weaknesses: Array<string>;
    };

    expect(output.known_weaknesses.length).toBeGreaterThan(0);
  });

  it('returns profile-level IHE security guidance for ATNA', () => {
    const output = getProtocolSecurity({ protocol: 'ATNA' }) as {
      recommended_controls: Array<string>;
    };

    expect(output.recommended_controls.length).toBeGreaterThan(0);
  });

  it('returns protocol security profile for IEEE 11073 SDC device interoperability', () => {
    const output = getProtocolSecurity({ protocol: 'IEEE_11073_SDC' }) as {
      known_weaknesses: Array<string>;
      configuration_guidance: Array<string>;
    };

    expect(output.known_weaknesses.length).toBeGreaterThan(0);
    expect(output.configuration_guidance.length).toBeGreaterThan(0);
  });

  it('returns protocol security profile for DICOMweb imaging APIs', () => {
    const output = getProtocolSecurity({ protocol: 'DICOMWEB' }) as {
      recommended_controls: Array<string>;
    };

    expect(output.recommended_controls).toContain('SCF-IAM');
  });

  it('returns protocol security profile for IHE XDS federated document exchange', () => {
    const output = getProtocolSecurity({ protocol: 'XDS' }) as {
      known_weaknesses: Array<string>;
    };

    expect(output.known_weaknesses.length).toBeGreaterThan(0);
  });

  it('returns protocol security profile for UDAP trust onboarding', () => {
    const output = getProtocolSecurity({ protocol: 'UDAP' }) as {
      recommended_controls: Array<string>;
    };

    expect(output.recommended_controls).toContain('SCF-IAM');
  });

  it('assesses clinical risk severity', () => {
    const output = assessClinicalRisk({
      threat_scenario: 'Compromise of infusion pump dosage controls in ICU',
      clinical_setting: 'ICU',
    }) as { harm_severity: string };

    expect(output.harm_severity).toBe('critical');
  });

  it('maps HIPAA safeguards', () => {
    const output = mapHipaaSafeguards({
      system_description: 'Hospital EHR and patient portal with ePHI',
      data_types: ['ephi'],
    }) as { technical_safeguards: Array<string> };

    expect(output.technical_safeguards.length).toBeGreaterThan(0);
  });

  it('maps FDA_524B requirement to current FDA device cybersecurity guidance metadata', () => {
    const output = mapToHealthcareStandards(db, {
      input_type: 'requirement',
      input_id: 'FDA_524B',
    }) as {
      mappings: Array<{ standard_id: string }>;
      standards: Array<{ version: string }>;
    };

    expect(output.mappings.some((item) => item.standard_id === 'fda_premarket_cyber_2023')).toBe(true);
    expect(output.standards.some((item) => item.version === '2026')).toBe(true);
  });

  it('maps IoMT architecture to IEEE 11073 and IEC 80001 standards', () => {
    const output = mapToHealthcareStandards(db, {
      input_type: 'architecture_pattern',
      input_id: 'hc-iomt',
    }) as {
      mappings: Array<{ standard_id: string }>;
    };

    expect(output.mappings.some((item) => item.standard_id === 'ieee_11073_sdc')).toBe(true);
    expect(output.mappings.some((item) => item.standard_id === 'iec_80001_1')).toBe(true);
  });

  it('maps NIS2 supply chain requirement to machine-readable advisory exchange standards', () => {
    const output = mapToHealthcareStandards(db, {
      input_type: 'requirement',
      input_id: 'NIS2_SUPPLY_CHAIN',
    }) as {
      mappings: Array<{ standard_id: string }>;
    };

    expect(output.mappings.some((item) => item.standard_id === 'csaf_2_0')).toBe(true);
    expect(output.mappings.some((item) => item.standard_id === 'vex')).toBe(true);
  });

  it('maps EHDS secondary-use requirement to cross-border exchange standards', () => {
    const output = mapToHealthcareStandards(db, {
      input_type: 'requirement',
      input_id: 'EHDS_SECONDARY_USE',
    }) as {
      mappings: Array<{ standard_id: string }>;
    };

    expect(output.mappings.some((item) => item.standard_id === 'hl7_ips')).toBe(true);
    expect(output.mappings.some((item) => item.standard_id === 'ihe_xds')).toBe(true);
  });

  it('maps TEFCA exchange requirement to TEFCA trust framework standards', () => {
    const output = mapToHealthcareStandards(db, {
      input_type: 'requirement',
      input_id: 'TEFCA_EXCHANGE',
    }) as {
      mappings: Array<{ standard_id: string }>;
    };

    expect(output.mappings.some((item) => item.standard_id === 'tefca_qtf')).toBe(true);
  });

  it('maps XCPD identity mismatch threat to patient-discovery and identity standards', () => {
    const output = mapToHealthcareStandards(db, {
      input_type: 'threat',
      input_id: 'th_xcpd_identity_mismatch',
    }) as {
      mappings: Array<{ standard_id: string }>;
    };

    expect(output.mappings.some((item) => item.standard_id === 'ihe_xcpd')).toBe(true);
    expect(output.mappings.some((item) => item.standard_id === 'ihe_pixm')).toBe(true);
  });

  it('maps IEEE 11073 command-injection threat to device interoperability and risk standards', () => {
    const output = mapToHealthcareStandards(db, {
      input_type: 'threat',
      input_id: 'th_11073_command_injection',
    }) as {
      mappings: Array<{ standard_id: string }>;
    };

    expect(output.mappings.some((item) => item.standard_id === 'ieee_11073_sdc')).toBe(true);
    expect(output.mappings.some((item) => item.standard_id === 'iso_14971')).toBe(true);
  });

  it('maps terminology-service poisoning threat to terminology and data-integrity standards', () => {
    const output = mapToHealthcareStandards(db, {
      input_type: 'threat',
      input_id: 'th_terminology_service_poisoning',
    }) as {
      mappings: Array<{ standard_id: string }>;
    };

    expect(output.mappings.some((item) => item.standard_id === 'snomed_ct')).toBe(true);
    expect(output.mappings.some((item) => item.standard_id === 'loinc')).toBe(true);
  });

  it('returns enriched threat intelligence for DICOMweb query-scrape scenarios', () => {
    const output = getHealthcareThreats(db, {
      query: 'DICOMweb query enumeration',
      include_playbooks: true,
      limit: 5,
    }) as {
      threats: Array<{
        threat_id: string;
        mitre_techniques: string[];
        response_playbook: { triage_priority: string } | null;
      }>;
    };

    const threat = output.threats.find((item) => item.threat_id === 'th_dicomweb_query_scrape');
    expect(threat).toBeDefined();
    expect((threat?.mitre_techniques ?? []).length).toBeGreaterThan(0);
    expect(threat?.response_playbook?.triage_priority).toBe('P1');
  });

  it('returns enriched threat intelligence for XDS registry poisoning scenarios', () => {
    const output = getHealthcareThreats(db, {
      query: 'XDS registry metadata poisoning',
      include_playbooks: true,
      limit: 5,
    }) as {
      threats: Array<{
        threat_id: string;
        response_playbook: { triage_priority: string } | null;
      }>;
    };

    const threat = output.threats.find((item) => item.threat_id === 'th_xds_registry_poisoning');
    expect(threat).toBeDefined();
    expect(threat?.response_playbook?.triage_priority).toBe('P1');
  });

  it('creates remediation backlog from baseline deltas', () => {
    const output = createRemediationBacklog({
      current_state: {
        implemented_controls: ['AU-2'],
      },
      target_baseline: {
        controls: [
          { control_id: 'AU-2', framework: 'NIST_800_53', priority: 'critical' },
          { control_id: 'AC-6', framework: 'NIST_800_53', priority: 'critical' },
        ],
      },
    }) as {
      summary: { missing_control_count: number };
    };

    expect(output.summary.missing_control_count).toBe(1);
  });

  it('returns threat response playbook details for known threat ids', () => {
    const output = getThreatResponsePlaybook(db, {
      threat_id: 'th_hl7_fhir_token_theft',
    }) as {
      triage_priority: string;
      immediate_containment_actions: string[];
      forensic_artifacts: string[];
    };

    expect(output.triage_priority.length).toBeGreaterThan(0);
    expect(output.immediate_containment_actions.length).toBeGreaterThan(0);
    expect(output.forensic_artifacts.length).toBeGreaterThan(0);
  });
});
