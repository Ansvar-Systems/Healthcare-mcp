import type { ToolError } from '../types.js';

const ADMINISTRATIVE = [
  'Security management process (risk analysis and risk management)',
  'Workforce security and role-based access governance',
  'Information access management and minimum necessary enforcement',
  'Security incident procedures and contingency planning',
  'Business associate agreement inventory and lifecycle tracking',
];

const PHYSICAL = [
  'Facility access controls and monitoring for clinical and IT environments',
  'Workstation use controls in shared clinical settings',
  'Device/media controls including disposal and reuse procedures',
];

const TECHNICAL = [
  'Unique user identification and emergency access procedures',
  'Automatic logoff for unattended clinical sessions',
  'Audit controls for patient data access and admin events',
  'Integrity controls for ePHI in storage and transmission',
  'Transmission security with encryption and secure channels',
];

export function mapHipaaSafeguards(args: unknown): Record<string, unknown> | ToolError {
  const input = (args ?? {}) as {
    system_description?: string;
    data_types?: string[];
  };

  if (!input.system_description || input.system_description.trim().length < 8) {
    return {
      error: 'system_description is required',
      hint: 'Describe system boundaries, user roles, and healthcare data processed.',
    };
  }

  const dataTypes = input.data_types ?? [];

  const additionalTechnical: string[] = [];
  const additionalAdministrative: string[] = [];

  if (dataTypes.includes('part2_substance_use') || dataTypes.includes('mental_health_records') || dataTypes.includes('mental_health')) {
    additionalAdministrative.push('Enhanced disclosure authorization governance and redisclosure controls');
    additionalTechnical.push('Field-level access controls and segmented data views for sensitive records');
  }

  if (dataTypes.includes('genetic_data')) {
    additionalTechnical.push('Advanced encryption and fine-grained export controls for genomic datasets');
  }

  return {
    system_description: input.system_description,
    data_types: dataTypes,
    administrative_safeguards: [...ADMINISTRATIVE, ...additionalAdministrative],
    physical_safeguards: PHYSICAL,
    technical_safeguards: [...TECHNICAL, ...additionalTechnical],
    references: [
      'HIPAA Security Rule 45 CFR 164.308',
      'HIPAA Security Rule 45 CFR 164.310',
      'HIPAA Security Rule 45 CFR 164.312',
      'NIST SP 800-66',
    ],
  };
}
