import { describe, expect, it } from 'vitest';
import { openDatabase } from '../src/db.js';
import { assessBreachObligations } from '../src/tools/assess_breach_obligations.js';
import { assessHealthcareApplicability } from '../src/tools/assess_healthcare_applicability.js';
import { buildEvidencePlan } from '../src/tools/build_evidence_plan.js';
import { classifyMedicalDevice } from '../src/tools/classify_medical_device.js';
import { getHealthcareThreats } from '../src/tools/get_healthcare_threats.js';
import { getThreatResponsePlaybook } from '../src/tools/get_threat_response_playbook.js';

describe('advanced healthcare expertise outputs', () => {
  const db = openDatabase(true);

  it('returns richer FDA/MDR/SaMD determination signals for high-risk software-device descriptions', () => {
    const output = classifyMedicalDevice(db, {
      description:
        'AI software controls autonomous dosing in a closed-loop implantable device for critical therapy decisions',
      region: 'US_EU',
    }) as {
      fda_class: string | null;
      mdr_class: string | null;
      samd_determination: { likely_samd: boolean; imdrf_category: string };
      ai_act_considerations: { high_risk_likelihood: boolean };
      applicable_standards: string[];
    };

    expect(output.fda_class).toBe('III');
    expect(output.mdr_class).toBe('III');
    expect(output.samd_determination.likely_samd).toBe(true);
    expect(output.samd_determination.imdrf_category).toBe('IV');
    expect(output.ai_act_considerations.high_risk_likelihood).toBe(true);
    expect(output.applicable_standards).toContain('iec_62304');
    expect(output.applicable_standards).toContain('iso_14971');
    expect(output.applicable_standards).toContain('iec_81001_5_1');
    expect(output.applicable_standards).toContain('iec_82304_1');
    expect(output.applicable_standards).toContain('aami_tir57');
  });

  it('builds jurisdiction-aware breach decision tree with local and family fallback routing', () => {
    const output = assessBreachObligations(db, {
      jurisdictions: ['US-CA', 'SE'],
      data_categories: ['ephi', 'ehds_secondary_use'],
      incident_summary:
        'Major ransomware incident disrupted clinical operations and exposed a secondary-use research dataset',
    }) as {
      strictest_deadline: { deadline_hours: number };
      notification_matrix: Array<{ jurisdiction: string; notifications: unknown[] }>;
      decision_tree: unknown[];
      notifications: Array<{ requested_jurisdiction: string }>;
    };

    expect(output.strictest_deadline.deadline_hours).toBeLessThanOrEqual(24);
    expect(output.notification_matrix.length).toBe(2);
    expect(output.decision_tree.length).toBeGreaterThan(0);
    expect(output.notifications.some((item) => item.requested_jurisdiction === 'US-CA')).toBe(true);
    expect(output.notifications.some((item) => item.requested_jurisdiction === 'SE')).toBe(true);
  });

  it('returns expanded audit evidence coverage for AI Act healthcare assessments', () => {
    const output = buildEvidencePlan(db, { audit_type: 'AI_ACT' }) as {
      templates: Array<{ template_id: string }>;
      artifact_checklist: string[];
      supported_audit_types: string[];
    };

    expect(output.templates.length).toBeGreaterThan(0);
    expect(output.supported_audit_types).toContain('AI_ACT');
    expect(
      output.artifact_checklist.some((item) =>
        item.toLowerCase().includes('risk management system documentation'),
      ),
    ).toBe(true);
  });

  it('builds threat-specific evidence appendix when threat ids are provided', () => {
    const output = buildEvidencePlan(db, {
      audit_type: 'THREAT_RESPONSE',
      threat_ids: ['th_11073_command_injection', 'th_dicomweb_query_scrape'],
    }) as {
      templates: Array<{ template_id: string }>;
      threat_evidence_appendix: Array<{
        threat_id: string;
        mapped_standards: Array<{ standard_id: string }>;
      }>;
      threat_artifact_checklist: string[];
    };

    expect(output.templates.length).toBeGreaterThan(0);
    const iomt = output.threat_evidence_appendix.find((item) => item.threat_id === 'th_11073_command_injection');
    expect(iomt).toBeDefined();
    expect((iomt?.mapped_standards ?? []).some((item) => item.standard_id === 'ieee_11073_sdc')).toBe(true);
    expect(output.threat_artifact_checklist.length).toBeGreaterThan(0);
  });

  it('returns explicit BAA/DPA/SCC and sensitive-chain contracting obligations in cross-border scenarios', () => {
    const output = assessHealthcareApplicability(db, {
      country: 'US-CA,DE',
      role: 'provider',
      system_types: ['telehealth', 'medical_device'],
      data_types: ['ephi', 'health_data', 'ehds_secondary_use', 'part2_substance_use'],
      additional_context: {
        uses_ai_for_clinical_decisions: true,
        has_medical_devices: true,
      },
    }) as {
      contracting_obligations: Array<{ agreement_type: string; applies: boolean }>;
    };

    const applicable = new Set(
      output.contracting_obligations
        .filter((obligation) => obligation.applies)
        .map((obligation) => obligation.agreement_type),
    );

    expect(applicable.has('BAA')).toBe(true);
    expect(applicable.has('DPA')).toBe(true);
    expect(applicable.has('SCC_OR_EQUIVALENT_TRANSFER_MECHANISM')).toBe(true);
    expect(applicable.has('PART2_REDISCLOSURE_CHAIN')).toBe(true);
    expect(applicable.has('EHDS_SECONDARY_USE_PERMIT')).toBe(true);
  });

  it('returns enriched expert threat intelligence with ATT&CK techniques and detection indicators', () => {
    const output = getHealthcareThreats(db, {
      pattern_id: 'hc-iomt',
      limit: 10,
    }) as {
      threats: Array<{
        threat_id: string;
        mitre_techniques: string[];
        likelihood_factors: string[];
        detection_indicators: string[];
        historical_incidents: string[];
      }>;
    };

    const ransomware = output.threats.find((threat) => threat.threat_id === 'th_iomt_ransomware_clinical_ops');
    expect(ransomware).toBeDefined();
    expect((ransomware?.mitre_techniques ?? []).length).toBeGreaterThan(0);
    expect((ransomware?.likelihood_factors ?? []).length).toBeGreaterThan(0);
    expect((ransomware?.detection_indicators ?? []).length).toBeGreaterThan(0);
    expect((ransomware?.historical_incidents ?? []).length).toBeGreaterThan(0);
  });

  it('returns dedicated response playbook for a known high-impact threat', () => {
    const output = getThreatResponsePlaybook(db, {
      threat_id: 'th_iomt_ransomware_clinical_ops',
    }) as {
      triage_priority: string;
      immediate_containment_actions: string[];
      clinical_safety_actions: string[];
      escalation_routes: string[];
    };

    expect(output.triage_priority).toBe('P1');
    expect(output.immediate_containment_actions.length).toBeGreaterThan(0);
    expect(output.clinical_safety_actions.length).toBeGreaterThan(0);
    expect(output.escalation_routes.length).toBeGreaterThan(0);
  });
});
