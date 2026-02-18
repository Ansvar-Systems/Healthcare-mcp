import { describe, expect, it } from 'vitest';
import { openDatabase } from '../src/db.js';
import { buildEvidencePlan } from '../src/tools/build_evidence_plan.js';
import { getHealthcareThreats } from '../src/tools/get_healthcare_threats.js';

describe('threat corpus integrity gate', () => {
  const db = openDatabase(true);

  it('ensures every threat has expert profile, playbook, regulation links, and control links', () => {
    const rows = db
      .prepare(
        `SELECT
           t.threat_id as threat_id,
           (SELECT COUNT(*) FROM threat_expert_profiles ep WHERE ep.threat_id = t.threat_id) as expert_count,
           (SELECT COUNT(*) FROM threat_response_playbooks rp WHERE rp.threat_id = t.threat_id) as playbook_count,
           (SELECT COUNT(*) FROM threat_regulation_links rl WHERE rl.threat_id = t.threat_id) as regulation_count,
           (SELECT COUNT(*) FROM threat_control_links cl WHERE cl.threat_id = t.threat_id) as control_count
         FROM threat_scenarios t
         ORDER BY t.threat_id`,
      )
      .all() as Array<{
      threat_id: string;
      expert_count: number;
      playbook_count: number;
      regulation_count: number;
      control_count: number;
    }>;

    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) {
      expect(row.expert_count, `${row.threat_id} missing threat_expert_profiles`).toBe(1);
      expect(row.playbook_count, `${row.threat_id} missing threat_response_playbooks`).toBe(1);
      expect(row.regulation_count, `${row.threat_id} missing threat_regulation_links`).toBeGreaterThan(0);
      expect(row.control_count, `${row.threat_id} missing threat_control_links`).toBeGreaterThan(0);
    }
  });

  it('ensures high-severity threats resolve to operationally actionable playbooks and ATT&CK technique coverage', () => {
    const output = getHealthcareThreats(db, { limit: 100, include_playbooks: true }) as {
      threats: Array<{
        threat_id: string;
        severity: string;
        mitre_techniques: string[];
        response_playbook: {
          triage_priority: string;
          immediate_containment_actions: string[];
          forensic_artifacts: string[];
          recovery_validation_checks: string[];
        } | null;
      }>;
    };

    const highImpact = output.threats.filter((threat) => threat.severity === 'critical');
    expect(highImpact.length).toBeGreaterThan(0);

    for (const threat of highImpact) {
      expect(threat.mitre_techniques.length, `${threat.threat_id} missing ATT&CK techniques`).toBeGreaterThan(0);
      expect(threat.response_playbook).not.toBeNull();
      expect(
        ['P1', 'P2'].includes(threat.response_playbook?.triage_priority ?? ''),
        `${threat.threat_id} unexpected triage priority`,
      ).toBe(true);
      expect(
        (threat.response_playbook?.immediate_containment_actions ?? []).length,
        `${threat.threat_id} missing containment actions`,
      ).toBeGreaterThan(0);
      expect(
        (threat.response_playbook?.forensic_artifacts ?? []).length,
        `${threat.threat_id} missing forensic artifacts`,
      ).toBeGreaterThan(0);
      expect(
        (threat.response_playbook?.recovery_validation_checks ?? []).length,
        `${threat.threat_id} missing recovery validation checks`,
      ).toBeGreaterThan(0);
    }
  });

  it('includes expanded advanced threat families for modern healthcare interoperability channels', () => {
    const expectedThreats = [
      'th_dicomweb_query_scrape',
      'th_11073_command_injection',
      'th_ncpdp_refill_replay',
      'th_x12_claims_tampering',
      'th_remote_monitoring_device_spoofing',
      'th_xds_registry_poisoning',
      'th_xcpd_identity_mismatch',
      'th_openehr_archetype_tampering',
      'th_udap_dynamic_client_abuse',
      'th_ccda_document_injection',
      'th_terminology_service_poisoning',
    ];

    const rows = db.prepare('SELECT threat_id FROM threat_scenarios ORDER BY threat_id').all() as Array<{
      threat_id: string;
    }>;
    const ids = new Set(rows.map((row) => row.threat_id));

    for (const threatId of expectedThreats) {
      expect(ids.has(threatId), `missing threat scenario ${threatId}`).toBe(true);
    }
  });

  it('ensures every threat has at least one direct technical standard mapping', () => {
    const rows = db
      .prepare(
        `SELECT
           t.threat_id as threat_id,
           (SELECT COUNT(*) FROM standard_mappings m WHERE m.input_type = 'threat' AND m.input_id = t.threat_id) as mapping_count
         FROM threat_scenarios t
         ORDER BY t.threat_id`,
      )
      .all() as Array<{ threat_id: string; mapping_count: number }>;

    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) {
      expect(row.mapping_count, `${row.threat_id} missing direct threat standard mapping`).toBeGreaterThan(0);
    }
  });

  it('can build threat-response evidence appendix for full corpus with mapped standards', () => {
    const threatRows = db.prepare('SELECT threat_id FROM threat_scenarios ORDER BY threat_id').all() as Array<{
      threat_id: string;
    }>;
    const threatIds = threatRows.map((row) => row.threat_id);

    const output = buildEvidencePlan(db, {
      audit_type: 'THREAT_RESPONSE',
      threat_ids: threatIds,
      include_threat_appendix: true,
    }) as {
      threat_evidence_appendix: Array<{ threat_id: string; mapped_standards: Array<unknown> }>;
    };

    expect(output.threat_evidence_appendix.length).toBe(threatIds.length);
    for (const item of output.threat_evidence_appendix) {
      expect(item.mapped_standards.length, `${item.threat_id} missing mapped standards in evidence appendix`).toBeGreaterThan(
        0,
      );
    }
  });
});
