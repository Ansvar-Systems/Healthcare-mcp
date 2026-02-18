import type { ToolError } from '../types.js';

function classifySeverity(text: string): 'low' | 'moderate' | 'high' | 'critical' {
  const lowered = text.toLowerCase();
  if (/(mortality|death|life[-\s]?threat|dosage|ventilator|alarm suppression|critical care)/.test(lowered)) {
    return 'critical';
  }
  if (/(treatment delay|misdiagnosis|clinical decision|surgery|icu|emergency)/.test(lowered)) {
    return 'high';
  }
  if (/(workflow disruption|delayed report|availability issue)/.test(lowered)) {
    return 'moderate';
  }
  return 'low';
}

function likelihoodFromContext(text: string): 'rare' | 'possible' | 'likely' {
  const lowered = text.toLowerCase();
  if (/(legacy|internet[-\s]?exposed|third[-\s]?party|shared workstation|unpatched)/.test(lowered)) {
    return 'likely';
  }
  if (/(segmented|zero trust|mfa|strict controls)/.test(lowered)) {
    return 'rare';
  }
  return 'possible';
}

export function assessClinicalRisk(args: unknown): Record<string, unknown> | ToolError {
  const input = (args ?? {}) as {
    threat_scenario?: string;
    device_context?: string;
    clinical_setting?: string;
  };

  if (!input.threat_scenario || input.threat_scenario.trim().length < 8) {
    return {
      error: 'threat_scenario is required',
      hint: 'Describe the threat scenario and expected clinical effect.',
    };
  }

  const context = [input.threat_scenario, input.device_context ?? '', input.clinical_setting ?? '']
    .join(' ')
    .trim();

  const harmSeverity = classifySeverity(context);
  const harmProbability = likelihoodFromContext(context);

  const riskAcceptability =
    harmSeverity === 'critical'
      ? 'not_acceptable_without_immediate_risk_controls'
      : harmSeverity === 'high'
        ? 'conditionally_acceptable_with_documented_risk_reduction'
        : 'acceptable_with_monitoring';

  return {
    threat_scenario: input.threat_scenario,
    device_context: input.device_context ?? null,
    clinical_setting: input.clinical_setting ?? null,
    safety_impact:
      harmSeverity === 'critical'
        ? 'Potential direct patient harm or life-threatening care disruption'
        : harmSeverity === 'high'
          ? 'Meaningful patient safety degradation with likely treatment impact'
          : 'Limited or indirect clinical safety impact',
    harm_severity: harmSeverity,
    harm_probability: harmProbability,
    risk_acceptability_per_iso14971: riskAcceptability,
    recommended_actions: [
      'Document hazard sequence and risk controls in ISO 14971 risk file.',
      'Tie risk controls to verification evidence and post-market monitoring.',
    ],
  };
}
