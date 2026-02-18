import type { SqlDatabase } from '../db.js';
import { parseJsonArray } from '../db.js';
import type { BuildEvidencePlanInput, ToolError } from '../types.js';

type TemplateRow = {
  template_id: string;
  audit_type: string;
  name: string;
  description: string;
  artifacts: string;
  linked_standards: string;
  linked_controls: string;
};

type ThreatRow = {
  threat_id: string;
  name: string;
  severity: 'critical' | 'high' | 'moderate' | 'low';
};

type ThreatPlaybookRow = {
  triage_priority: 'P1' | 'P2' | 'P3';
  immediate_containment_actions: string;
  clinical_safety_actions: string;
  forensic_artifacts: string;
  recovery_validation_checks: string;
  communication_requirements: string;
  escalation_routes: string;
};

type ThreatRegulationLinkRow = {
  source_mcp: string;
  requirement_ref: string;
  obligation_summary: string;
};

type ThreatControlLinkRow = {
  control_framework: string;
  control_id: string;
  control_summary: string;
};

type ThreatStandardRow = {
  standard_id: string;
  name: string;
  mapping_type: string;
  rationale: string;
};

function unique(values: string[]): string[] {
  return [...new Set(values)];
}

export function buildEvidencePlan(
  db: SqlDatabase,
  args: unknown,
): Record<string, unknown> | ToolError {
  const input = (args ?? {}) as BuildEvidencePlanInput & {
    baseline?: {
      controls?: Array<{ control_id: string }>;
      prioritized_controls?: Array<{ control_id: string }>;
    };
    threats?: string[];
  };

  const rows = input.audit_type
    ? (db
        .prepare(
          `SELECT template_id, audit_type, name, description, artifacts,
                  linked_standards, linked_controls
           FROM evidence_templates
           WHERE upper(audit_type) = upper(?)
           ORDER BY template_id`,
        )
        .all(input.audit_type) as TemplateRow[])
    : (db
        .prepare(
          `SELECT template_id, audit_type, name, description, artifacts,
                  linked_standards, linked_controls
           FROM evidence_templates
           ORDER BY audit_type, template_id`,
        )
        .all() as TemplateRow[]);

  const supportedAuditTypes = db
    .prepare('SELECT DISTINCT audit_type FROM evidence_templates ORDER BY audit_type')
    .all() as Array<{ audit_type: string }>;

  if (rows.length === 0) {
    return {
      error: 'No evidence template found for the requested audit_type.',
      hint: `Supported audit types: ${supportedAuditTypes.map((item) => item.audit_type).join(', ')}.`,
    };
  }

  const templates = rows.map((row) => ({
    template_id: row.template_id,
    audit_type: row.audit_type,
    name: row.name,
    description: row.description,
    artifacts: parseJsonArray(row.artifacts),
    linked_standards: parseJsonArray(row.linked_standards),
    linked_controls: parseJsonArray(row.linked_controls),
  }));

  const baseArtifactChecklist = unique(templates.flatMap((template) => template.artifacts));

  const baselineControls =
    input.baseline_control_ids ??
    input.baseline?.controls?.map((item) => item.control_id) ??
    input.baseline?.prioritized_controls?.map((item) => item.control_id) ??
    [];

  const requestedThreatIds = unique(
    (input.threat_ids ?? input.threats ?? [])
      .map((threatId) => threatId.trim())
      .filter((threatId) => threatId.length > 0),
  );
  const includeThreatAppendix = input.include_threat_appendix ?? requestedThreatIds.length > 0;

  const threatEvidenceAppendix = [];
  const threatIdsNotFound: string[] = [];

  for (const threatId of requestedThreatIds) {
    const threat = db
      .prepare('SELECT threat_id, name, severity FROM threat_scenarios WHERE lower(threat_id) = lower(?)')
      .get(threatId) as ThreatRow | undefined;

    if (!threat) {
      threatIdsNotFound.push(threatId);
      continue;
    }

    const playbook = db
      .prepare(
        `SELECT triage_priority, immediate_containment_actions, clinical_safety_actions,
                forensic_artifacts, recovery_validation_checks, communication_requirements, escalation_routes
         FROM threat_response_playbooks
         WHERE threat_id = ?`,
      )
      .get(threat.threat_id) as ThreatPlaybookRow | undefined;

    const regulationLinks = db
      .prepare(
        `SELECT source_mcp, requirement_ref, obligation_summary
         FROM threat_regulation_links
         WHERE threat_id = ?
         ORDER BY source_mcp, requirement_ref`,
      )
      .all(threat.threat_id) as ThreatRegulationLinkRow[];

    const controlLinks = db
      .prepare(
        `SELECT control_framework, control_id, control_summary
         FROM threat_control_links
         WHERE threat_id = ?
         ORDER BY control_framework, control_id`,
      )
      .all(threat.threat_id) as ThreatControlLinkRow[];

    const mappedStandards = db
      .prepare(
        `SELECT m.standard_id, s.name, m.mapping_type, m.rationale
         FROM standard_mappings m
         JOIN technical_standards s ON s.standard_id = m.standard_id
         WHERE m.input_type = 'threat' AND lower(m.input_id) = lower(?)
         ORDER BY m.standard_id`,
      )
      .all(threat.threat_id) as ThreatStandardRow[];

    const forensicArtifacts = playbook ? parseJsonArray(playbook.forensic_artifacts) : [];
    const recoveryValidationChecks = playbook ? parseJsonArray(playbook.recovery_validation_checks) : [];
    const communicationRequirements = playbook ? parseJsonArray(playbook.communication_requirements) : [];
    const escalationRoutes = playbook ? parseJsonArray(playbook.escalation_routes) : [];

    threatEvidenceAppendix.push({
      threat_id: threat.threat_id,
      threat_name: threat.name,
      severity: threat.severity,
      triage_priority: playbook?.triage_priority ?? null,
      forensic_artifacts: forensicArtifacts,
      recovery_validation_checks: recoveryValidationChecks,
      communication_requirements: communicationRequirements,
      escalation_routes: escalationRoutes,
      linked_regulatory_routes: regulationLinks,
      linked_control_routes: controlLinks,
      mapped_standards: mappedStandards,
      suggested_artifact_bundle: unique([
        ...forensicArtifacts,
        ...recoveryValidationChecks,
        ...communicationRequirements.map((item) => `Communication evidence: ${item}`),
      ]),
    });
  }

  const threatArtifactChecklist = unique(
    threatEvidenceAppendix.flatMap((item) => item.suggested_artifact_bundle),
  );
  const artifactChecklist = includeThreatAppendix
    ? unique([...baseArtifactChecklist, ...threatArtifactChecklist])
    : baseArtifactChecklist;

  return {
    requested_audit_type: input.audit_type ?? 'ALL',
    supported_audit_types: supportedAuditTypes.map((item) => item.audit_type),
    templates,
    artifact_checklist: artifactChecklist,
    baseline_control_ids: baselineControls,
    requested_threat_ids: requestedThreatIds,
    threat_ids_not_found: threatIdsNotFound,
    threat_evidence_appendix: includeThreatAppendix ? threatEvidenceAppendix : [],
    threat_artifact_checklist: includeThreatAppendix ? threatArtifactChecklist : [],
    workflow_note:
      'Use compare_jurisdictions and assess_breach_obligations to append jurisdiction-specific notification/reporting artifacts; provide threat_ids to generate threat-level incident evidence annexes.',
  };
}
