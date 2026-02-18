import type { ToolError } from '../types.js';

type BaselineControl = {
  control_id: string;
  framework: string;
  priority?: 'critical' | 'high' | 'moderate';
  rationale?: string;
};

function effortFromPriority(priority: string): 'small' | 'medium' | 'large' {
  if (priority === 'critical') {
    return 'large';
  }
  if (priority === 'high') {
    return 'medium';
  }
  return 'small';
}

export function createRemediationBacklog(args: unknown): Record<string, unknown> | ToolError {
  const input = (args ?? {}) as {
    current_state?: {
      implemented_controls?: string[];
      known_gaps?: string[];
    };
    target_baseline?: {
      controls?: BaselineControl[];
      prioritized_controls?: BaselineControl[];
    };
  };

  const current = input.current_state ?? {};
  const target = input.target_baseline ?? {};

  const implemented = new Set((current.implemented_controls ?? []).map((item) => item.toUpperCase()));
  const targetControls = target.controls ?? target.prioritized_controls ?? [];

  if (targetControls.length === 0) {
    return {
      error: 'target_baseline.controls or target_baseline.prioritized_controls is required',
      hint: 'Pass output from build_control_baseline/build_healthcare_baseline.',
    };
  }

  const backlogItems = targetControls
    .filter((control) => !implemented.has(control.control_id.toUpperCase()))
    .map((control, index) => {
      const priority = control.priority ?? 'moderate';
      return {
        id: `rb-${String(index + 1).padStart(3, '0')}`,
        action: `Implement ${control.framework} ${control.control_id}`,
        priority,
        effort_estimate: effortFromPriority(priority),
        regulation_basis: ['US_Regulations_MCP', 'EU_Regulations_MCP'],
        risk_reduction:
          priority === 'critical'
            ? 'high_immediate'
            : priority === 'high'
              ? 'high'
              : 'moderate',
        rationale: control.rationale ?? 'Baseline gap closure for healthcare threat profile.',
      };
    });

  const knownGaps = (current.known_gaps ?? []).map((gap, index) => ({
    id: `kg-${String(index + 1).padStart(3, '0')}`,
    action: gap,
    priority: 'high',
    effort_estimate: 'medium',
    regulation_basis: ['context_specific'],
    risk_reduction: 'high',
    rationale: 'User-declared current-state gap.',
  }));

  return {
    backlog_items: [...backlogItems, ...knownGaps],
    summary: {
      target_control_count: targetControls.length,
      missing_control_count: backlogItems.length,
      declared_gap_count: knownGaps.length,
    },
  };
}
