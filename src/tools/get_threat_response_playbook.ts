import type { SqlDatabase } from '../db.js';
import { parseJsonArray } from '../db.js';
import type { ToolError } from '../types.js';
import { buildCitation } from '../utils/citation.js';

type PlaybookRow = {
  threat_id: string;
  triage_priority: 'P1' | 'P2' | 'P3';
  immediate_containment_actions: string;
  clinical_safety_actions: string;
  forensic_artifacts: string;
  recovery_validation_checks: string;
  communication_requirements: string;
  escalation_routes: string;
};

export function getThreatResponsePlaybook(
  db: SqlDatabase,
  args: unknown,
): Record<string, unknown> | ToolError {
  const input = (args ?? {}) as { threat_id?: string };
  if (!input.threat_id || input.threat_id.trim().length < 3) {
    return {
      error: 'threat_id is required',
      hint: 'Use a threat_id from get_healthcare_threats, e.g. th_iomt_ransomware_clinical_ops.',
    };
  }

  const row = db
    .prepare(
      `SELECT threat_id, triage_priority, immediate_containment_actions, clinical_safety_actions,
              forensic_artifacts, recovery_validation_checks, communication_requirements, escalation_routes
       FROM threat_response_playbooks
       WHERE threat_id = ?`,
    )
    .get(input.threat_id) as PlaybookRow | undefined;

  if (!row) {
    return {
      error: `No response playbook found for threat_id: ${input.threat_id}`,
      hint: 'Call get_healthcare_threats first and use one of the returned threat IDs.',
    };
  }

  return {
    threat_id: row.threat_id,
    triage_priority: row.triage_priority,
    immediate_containment_actions: parseJsonArray(row.immediate_containment_actions),
    clinical_safety_actions: parseJsonArray(row.clinical_safety_actions),
    forensic_artifacts: parseJsonArray(row.forensic_artifacts),
    recovery_validation_checks: parseJsonArray(row.recovery_validation_checks),
    communication_requirements: parseJsonArray(row.communication_requirements),
    escalation_routes: parseJsonArray(row.escalation_routes),
    workflow_guidance: [
      'Execute containment and clinical-safety actions in parallel when patient-impact risk is present.',
      'Preserve forensic artifacts before disruptive recovery actions where feasible.',
      'Route legal/regulatory obligations through authoritative MCP endpoints using escalation_routes.',
    ],
    _citation: buildCitation(
      row.threat_id,
      `Threat response playbook: ${row.threat_id} (${row.triage_priority})`,
      'get_threat_response_playbook',
      { threat_id: input.threat_id! },
    ),
  };
}
