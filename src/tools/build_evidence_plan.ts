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

export function buildEvidencePlan(
  db: SqlDatabase,
  args: unknown,
): Record<string, unknown> | ToolError {
  const input = (args ?? {}) as BuildEvidencePlanInput & {
    baseline?: {
      controls?: Array<{ control_id: string }>;
      prioritized_controls?: Array<{ control_id: string }>;
    };
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

  const artifactChecklist = [...new Set(templates.flatMap((template) => template.artifacts))];

  const baselineControls =
    input.baseline_control_ids ??
    input.baseline?.controls?.map((item) => item.control_id) ??
    input.baseline?.prioritized_controls?.map((item) => item.control_id) ??
    [];

  return {
    requested_audit_type: input.audit_type ?? 'ALL',
    supported_audit_types: supportedAuditTypes.map((item) => item.audit_type),
    templates,
    artifact_checklist: artifactChecklist,
    baseline_control_ids: baselineControls,
    workflow_note:
      'Use compare_jurisdictions and assess_breach_obligations to append jurisdiction-specific notification and reporting artifacts.',
  };
}
