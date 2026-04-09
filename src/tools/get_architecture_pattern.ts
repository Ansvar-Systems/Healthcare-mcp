import type { SqlDatabase } from '../db.js';
import { parseJsonArray } from '../db.js';
import type { GetArchitecturePatternInput, ToolError } from '../types.js';
import { responseMeta } from './response-meta.js';

type PatternRow = {
  pattern_id: string;
  name: string;
  description: string;
  primary_system: string;
};

type ComponentRow = {
  component_id: string;
  name: string;
  component_type: string;
  description: string;
  trust_zone: string;
};

type BoundaryRow = {
  boundary_id: string;
  boundary_name: string;
  from_zone: string;
  to_zone: string;
  risk_note: string;
};

type DataFlowRow = {
  flow_id: string;
  flow_name: string;
  source_component: string;
  target_component: string;
  data_categories: string;
  protocols: string;
};

type WeakPointRow = {
  weak_point_id: string;
  weak_point: string;
  severity: string;
  rationale: string;
};

export function getArchitecturePattern(
  db: SqlDatabase,
  args: unknown,
): Record<string, unknown> | ToolError {
  const input = (args ?? {}) as GetArchitecturePatternInput;

  let row: PatternRow | undefined;

  if (input.pattern_id) {
    row = db
      .prepare(
        'SELECT pattern_id, name, description, primary_system FROM architecture_patterns WHERE pattern_id = ?',
      )
      .get(input.pattern_id) as PatternRow | undefined;
  }

  if (!row && input.system_type) {
    row = db
      .prepare(
        'SELECT pattern_id, name, description, primary_system FROM architecture_patterns WHERE lower(primary_system) = lower(?) LIMIT 1',
      )
      .get(input.system_type) as PatternRow | undefined;
  }

  if (!row) {
    const available = db
      .prepare('SELECT pattern_id, name, primary_system FROM architecture_patterns ORDER BY pattern_id')
      .all() as Array<{ pattern_id: string; name: string; primary_system: string }>;

    return {
      error: 'No architecture pattern matched the request.',
      hint: 'Use pattern_id or system_type from available_patterns.',
      available_patterns: available,
      _error_type: 'not_found',
      ...responseMeta(),
    };
  }

  const components = db
    .prepare(
      'SELECT component_id, name, component_type, description, trust_zone FROM pattern_components WHERE pattern_id = ? ORDER BY component_id',
    )
    .all(row.pattern_id) as ComponentRow[];

  const trustBoundaries = db
    .prepare(
      'SELECT boundary_id, boundary_name, from_zone, to_zone, risk_note FROM pattern_trust_boundaries WHERE pattern_id = ? ORDER BY boundary_id',
    )
    .all(row.pattern_id) as BoundaryRow[];

  const flows = db
    .prepare(
      'SELECT flow_id, flow_name, source_component, target_component, data_categories, protocols FROM pattern_data_flows WHERE pattern_id = ? ORDER BY flow_id',
    )
    .all(row.pattern_id) as DataFlowRow[];

  const weakPoints = db
    .prepare(
      'SELECT weak_point_id, weak_point, severity, rationale FROM pattern_weak_points WHERE pattern_id = ? ORDER BY weak_point_id',
    )
    .all(row.pattern_id) as WeakPointRow[];

  const integrationPoints = [...new Set(flows.flatMap((flow) => parseJsonArray(flow.protocols)))];
  const topology = {
    pattern_id: row.pattern_id,
    nodes: components.map((component) => component.component_id),
    edges: flows.map((flow) => ({
      from: flow.source_component,
      to: flow.target_component,
      flow_id: flow.flow_id,
    })),
  };

  return {
    pattern: row,
    topology,
    components,
    trust_boundaries: trustBoundaries,
    data_flows: flows.map((flow) => ({
      ...flow,
      data_categories: parseJsonArray(flow.data_categories),
      protocols: parseJsonArray(flow.protocols),
    })),
    integration_points: integrationPoints,
    known_weak_points: weakPoints,
    known_weaknesses: weakPoints,
    modeling_guidance: [
      'Validate all zone transitions with explicit authN/authZ controls.',
      'Map each weak point to threat scenarios and required controls.',
      'Trace data flow elements to specific health data categories before severity scoring.',
    ],
    _citation: {
      canonical_ref: `healthcare-mcp:pattern/${row.pattern_id}`,
      display_text: row.name,
      lookup: `get_architecture_pattern?pattern_id=${row.pattern_id}`,
    },
    ...responseMeta(),
  };
}
