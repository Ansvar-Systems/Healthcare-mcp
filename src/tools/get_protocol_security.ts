import type { ToolError } from '../types.js';

type ProtocolProfile = {
  security_features: string[];
  known_weaknesses: string[];
  recommended_controls: string[];
  configuration_guidance: string[];
};

const PROFILES: Record<string, ProtocolProfile> = {
  hl7v2: {
    security_features: ['Widely implemented messaging standard', 'Supports transport wrapping (TLS/VPN)'],
    known_weaknesses: [
      'No native authentication or encryption at message layer',
      'Prone to message injection when interfaces are weakly segmented',
    ],
    recommended_controls: ['SCF-AC', 'SCF-SC', 'SCF-AU', 'NIST_800_53:SC-7'],
    configuration_guidance: [
      'Terminate HL7 traffic through authenticated integration gateways.',
      'Apply strict sender allow-listing and schema validation.',
      'Log and alert on anomalous segment/value patterns (e.g., PID/OBX anomalies).',
    ],
  },
  fhir: {
    security_features: ['RESTful APIs with modern auth patterns', 'SMART on FHIR OAuth2/OIDC ecosystem'],
    known_weaknesses: [
      'Scope misconfiguration can allow bulk exfiltration',
      'Token reuse and overly long refresh token lifetimes increase breach blast radius',
    ],
    recommended_controls: ['SCF-AC', 'SCF-IAM', 'SCF-AU', 'NIST_800_53:AC-6'],
    configuration_guidance: [
      'Use least-privilege SMART scopes and short token lifetimes.',
      'Enforce patient-level access controls and query-size limits.',
      'Instrument fine-grained API audit logs for FHIR resource access.',
    ],
  },
  fhir_r4: {
    security_features: ['Stable FHIR release for production interoperability', 'SMART on FHIR integration profile support'],
    known_weaknesses: [
      'Mis-scoped resource access can enable broad patient-data reads',
      'Search/export endpoints can expose large datasets when guardrails are weak',
    ],
    recommended_controls: ['SCF-AC', 'SCF-IAM', 'SCF-AU', 'NIST_800_53:AC-4'],
    configuration_guidance: [
      'Use compartment-aware and patient-level authorization checks.',
      'Apply pagination/export limits and high-risk endpoint monitoring.',
      'Bind tokens to app/client context and rotate signing keys.',
    ],
  },
  fhir_r5: {
    security_features: ['Expanded interoperability resources', 'Improved event and exchange patterns'],
    known_weaknesses: [
      'Expanded surface area increases misconfiguration risk across new resources',
      'Backward-compatibility bridges may weaken consistent authorization enforcement',
    ],
    recommended_controls: ['SCF-AC', 'SCF-IAM', 'SCF-AU', 'NIST_800_53:SA-8'],
    configuration_guidance: [
      'Treat R5 migration as a security architecture change with threat-model updates.',
      'Harden compatibility layers between R4/R5 ecosystems.',
      'Validate per-resource authorization and audit completeness before go-live.',
    ],
  },
  smart_on_fhir: {
    security_features: ['Standardized launch context', 'OAuth2/OIDC authorization framework'],
    known_weaknesses: [
      'App registration and redirect URI weaknesses can enable token theft',
      'Backend service grants can be over-scoped in integrations',
    ],
    recommended_controls: ['SCF-IAM', 'SCF-AC', 'SCF-SDLC'],
    configuration_guidance: [
      'Enforce strict redirect URI verification and app attestation.',
      'Use confidential clients for backend services and rotate secrets frequently.',
      'Continuously review granted scopes per connected app.',
    ],
  },
  dicom: {
    security_features: ['Mature imaging transfer and metadata model', 'Security profiles available through IHE'],
    known_weaknesses: [
      'PHI may be embedded in metadata headers',
      'Legacy deployments often lack strong transport protections',
    ],
    recommended_controls: ['SCF-DLP', 'SCF-SC', 'SCF-AU', 'IEC_80001_SEGMENTATION'],
    configuration_guidance: [
      'Apply de-identification and metadata-sanitization workflows before export.',
      'Segment modality networks from enterprise IT and internet-facing zones.',
      'Require secure transport and authenticated peer endpoints.',
    ],
  },
  ihe: {
    security_features: ['Profile-based interoperability and security controls (ATNA/XUA/IUA)'],
    known_weaknesses: [
      'Inconsistent profile implementation across vendors',
      'Token and audit trust assumptions may break in multi-org exchanges',
    ],
    recommended_controls: ['SCF-IAM', 'SCF-AU', 'SCF-SCRM'],
    configuration_guidance: [
      'Validate profile conformance in integration testing.',
      'Harden trust anchors and token validation for cross-organization exchanges.',
      'Centralize security event correlation across participating systems.',
    ],
  },
  ihe_atna: {
    security_features: ['Audit Trail and Node Authentication baseline for distributed healthcare exchanges'],
    known_weaknesses: [
      'Partial node-authentication deployment breaks trust assumptions',
      'Audit event gaps limit forensic confidence during incidents',
    ],
    recommended_controls: ['SCF-AU', 'SCF-IAM', 'SCF-SC'],
    configuration_guidance: [
      'Require authenticated node trust and certificate governance.',
      'Centralize ATNA audit ingestion and integrity protection.',
      'Test failure paths for unauthenticated or mismatched nodes.',
    ],
  },
  ihe_xua: {
    security_features: ['Cross-enterprise user identity assertion for federated health workflows'],
    known_weaknesses: [
      'Improper assertion validation can enable impersonation',
      'Clock skew and trust-anchor misconfiguration can invalidate assurance',
    ],
    recommended_controls: ['SCF-IAM', 'SCF-AC', 'SCF-AU'],
    configuration_guidance: [
      'Validate assertion issuer trust chains and audience restrictions.',
      'Enforce short token/assertion lifetimes and replay protections.',
      'Correlate assertion identity with downstream authorization decisions.',
    ],
  },
  ihe_iua: {
    security_features: ['OAuth2-compatible authorization profile for healthcare APIs'],
    known_weaknesses: [
      'Over-broad scopes and client misregistration increase data exfiltration risk',
      'Token introspection and revocation gaps prolong compromise windows',
    ],
    recommended_controls: ['SCF-IAM', 'SCF-AC', 'SCF-AU'],
    configuration_guidance: [
      'Use least-privilege scopes with strict client registration controls.',
      'Enforce token revocation/introspection for high-risk workflows.',
      'Instrument authorization decisions and consent context in audit logs.',
    ],
  },
  ihe_ser: {
    security_features: ['Structured security event reporting across federated participants'],
    known_weaknesses: [
      'Inconsistent event taxonomy prevents reliable cross-entity correlation',
      'Delayed event reporting degrades coordinated incident response',
    ],
    recommended_controls: ['SCF-AU', 'SCF-IR', 'SCF-SCRM'],
    configuration_guidance: [
      'Standardize event schemas and severity levels across participants.',
      'Establish rapid event-sharing SLAs and escalation criteria.',
      'Continuously validate feed completeness and alerting fidelity.',
    ],
  },
};

export function getProtocolSecurity(args: unknown): Record<string, unknown> | ToolError {
  const input = (args ?? {}) as { protocol?: string };

  if (!input.protocol) {
    return {
      error: 'protocol is required',
      hint: 'Use HL7v2, FHIR, SMART_ON_FHIR, DICOM, or IHE.',
    };
  }

  const normalized = input.protocol.toLowerCase().replace(/[^a-z0-9]+/g, '_');

  const aliasMap: Record<string, string> = {
    hl7v2: 'hl7v2',
    hl7_v2: 'hl7v2',
    fhir: 'fhir',
    fhir_r4: 'fhir_r4',
    fhir_r5: 'fhir_r5',
    smart_on_fhir: 'smart_on_fhir',
    smart: 'smart_on_fhir',
    dicom: 'dicom',
    ihe: 'ihe',
    ihe_profile: 'ihe',
    atna: 'ihe_atna',
    ihe_atna: 'ihe_atna',
    xua: 'ihe_xua',
    ihe_xua: 'ihe_xua',
    iua: 'ihe_iua',
    ihe_iua: 'ihe_iua',
    ser: 'ihe_ser',
    ihe_ser: 'ihe_ser',
  };

  const key = aliasMap[normalized];
  if (!key || !PROFILES[key]) {
    return {
      error: `Unsupported protocol: ${input.protocol}`,
      hint:
        'Supported protocols: HL7v2, FHIR, FHIR_R4, FHIR_R5, SMART_ON_FHIR, DICOM, IHE, ATNA, XUA, IUA, SeR.',
    };
  }

  return {
    protocol: input.protocol,
    ...PROFILES[key],
  };
}
