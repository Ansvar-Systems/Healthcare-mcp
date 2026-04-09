import type { SqlDatabase } from '../db.js';
import type { BuildHealthcareBaselineInput, ToolError } from '../types.js';
import { responseMeta } from './response-meta.js';

type BaselineControl = {
  control_id: string;
  framework: string;
  priority: 'critical' | 'high' | 'moderate';
  rationale: string;
  healthcare_context: string;
};

function buildCoreControls(): BaselineControl[] {
  return [
    {
      control_id: 'AC-6',
      framework: 'NIST_800_53',
      priority: 'critical',
      rationale: 'Limit privileged and API scope access for clinical systems.',
      healthcare_context: 'Prevents over-broad access to patient records via integrations.',
    },
    {
      control_id: 'AU-2',
      framework: 'NIST_800_53',
      priority: 'critical',
      rationale: 'Capture auditable clinical data access and admin actions.',
      healthcare_context: 'Required for breach reconstruction and regulator defensibility.',
    },
    {
      control_id: 'IR-4',
      framework: 'NIST_800_53',
      priority: 'critical',
      rationale: 'Establish incident handling with healthcare outage scenarios.',
      healthcare_context: 'Supports patient diversion and care continuity during incidents.',
    },
    {
      control_id: 'SR-5',
      framework: 'NIST_800_53',
      priority: 'high',
      rationale: 'Supplier risk management for EHR and device vendors.',
      healthcare_context: 'Addresses concentration risk in healthcare software/device supply chains.',
    },
    {
      control_id: 'PR.PS-02',
      framework: 'NIST_CSF_2.0',
      priority: 'high',
      rationale: 'Ensure secure software lifecycle and patch governance.',
      healthcare_context: 'Mitigates unpatched vulnerabilities in clinical platforms and devices.',
    },
  ];
}

export function buildHealthcareBaseline(
  db: SqlDatabase,
  args: unknown,
): Record<string, unknown> | ToolError {
  const input = args as BuildHealthcareBaselineInput & {
    org_profile?: BuildHealthcareBaselineInput['organization_profile'];
  };
  const profile = input?.organization_profile ?? input?.org_profile;

  if (!profile || !Array.isArray(profile.jurisdictions) || !Array.isArray(profile.data_categories)) {
    return {
      error: 'organization_profile with jurisdictions and data_categories is required',
      hint: 'Include has_medical_devices to get device-specific baseline controls.',
      _error_type: 'invalid_input',
      ...responseMeta(),
    };
  }

  const controls = buildCoreControls();

  if (profile.has_medical_devices) {
    controls.push(
      {
        control_id: 'IEC_80001_SEGMENTATION',
        framework: 'IEC_80001_1',
        priority: 'critical',
        rationale: 'Segment medical device networks and enforce managed interfaces.',
        healthcare_context: 'Reduces ransomware and lateral movement from IT to IoMT zones.',
      },
      {
        control_id: 'FDA_524B_VULN_MGMT',
        framework: 'FDA_524B',
        priority: 'high',
        rationale: 'Maintain coordinated vulnerability disclosure and remediation process.',
        healthcare_context: 'Expected in premarket and postmarket device cybersecurity reviews.',
      },
    );
  }

  if (profile.data_categories.includes('part2_substance_use') || profile.data_categories.includes('genetic_data')) {
    controls.push({
      control_id: 'PRIVACY_FIELD_LEVEL_ENCRYPTION',
      framework: 'ISO_27701',
      priority: 'critical',
      rationale: 'Use granular data minimization and encryption for highly sensitive datasets.',
      healthcare_context: 'Protects records with elevated disclosure restrictions.',
    });
  }

  const uniqueControls = Array.from(
    new Map(controls.map((item) => [`${item.framework}:${item.control_id}`, item])).values(),
  );

  const standardRows = db
    .prepare('SELECT standard_id, name FROM technical_standards ORDER BY standard_id')
    .all() as Array<{ standard_id: string; name: string }>;

  return {
    organization_profile: profile,
    prioritized_controls: uniqueControls,
    standards_context: standardRows,
    implementation_routes: {
      controls_source: 'Security_Controls_MCP',
      regulations_source: ['US_Regulations_MCP', 'EU_Regulations_MCP', 'law MCPs'],
    },
    next_actions: [
      'Map each control to authoritative control text through Security Controls MCP.',
      'Generate evidence requirements with build_evidence_plan.',
    ],
    ...responseMeta(),
  };
}
