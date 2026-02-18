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
  smart_backend_services: {
    security_features: [
      'Backend-only OAuth2 JWT client assertions for non-user SMART workflows',
      'Supports high-volume system-to-system exchange with scoped access tokens',
    ],
    known_weaknesses: [
      'Over-broad system scopes can expose full patient populations',
      'Long-lived private keys and weak key custody increase token forgery risk',
    ],
    recommended_controls: ['SCF-IAM', 'SCF-AC', 'SCF-SDLC', 'NIST_800_53:IA-5'],
    configuration_guidance: [
      'Use narrow system scopes and compartment-limited export permissions.',
      'Use short-lived signed JWT assertions and hardware-protected signing keys.',
      'Rotate keys with automated trust-store rollover and replay detection.',
    ],
  },
  fhir_bulk_data: {
    security_features: [
      'Asynchronous export/import for population-scale FHIR workloads',
      'Authorization-aware bulk operations with auditable job state',
    ],
    known_weaknesses: [
      'Misconfigured export jobs can leak large cohorts rapidly',
      'Insufficient queue isolation may expose cross-tenant datasets',
    ],
    recommended_controls: ['SCF-AC', 'SCF-IAM', 'SCF-AU', 'SCF-DLP'],
    configuration_guidance: [
      'Require explicit approval and patient/cohort scoping for bulk jobs.',
      'Encrypt export artifacts at rest and enforce short retention windows.',
      'Bind job identifiers to requesting principal and monitor abnormal volumes.',
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
  dicomweb: {
    security_features: ['RESTful imaging APIs (QIDO-RS, WADO-RS, STOW-RS)', 'Browser-friendly retrieval and rendering support'],
    known_weaknesses: [
      'Web API exposure increases risk of unauthorized bulk image enumeration',
      'Metadata response fields may leak patient identifiers across query paths',
    ],
    recommended_controls: ['SCF-IAM', 'SCF-AC', 'SCF-AU', 'SCF-DLP'],
    configuration_guidance: [
      'Enforce strict per-study authorization and query throttling controls.',
      'Filter/redact sensitive metadata fields for non-clinical consumers.',
      'Require mTLS or strong token validation for server-to-server imaging exchange.',
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
  ihe_xds: {
    security_features: ['Cross-enterprise document registry/repository exchange model', 'Supports federated clinical document sharing across organizations'],
    known_weaknesses: [
      'Affinity-domain trust misconfiguration can expose broad document access',
      'Document metadata and repository endpoints may leak sensitive context when weakly scoped',
    ],
    recommended_controls: ['SCF-IAM', 'SCF-AC', 'SCF-AU', 'SCF-SCRM'],
    configuration_guidance: [
      'Enforce strict affinity-domain trust anchors and participant onboarding validation.',
      'Apply document-level authorization and metadata minimization for query responses.',
      'Correlate registry/repository access events with federated identity assertions.',
    ],
  },
  ihe_mhd: {
    security_features: ['REST/FHIR-oriented mobile document sharing profile', 'Supports modernized document exchange in federated care ecosystems'],
    known_weaknesses: [
      'Mobile/API delivery paths can widen document enumeration and replay risk',
      'Token/scope misconfiguration can expose broad document sets across communities',
    ],
    recommended_controls: ['SCF-IAM', 'SCF-AC', 'SCF-AU', 'SCF-DLP'],
    configuration_guidance: [
      'Apply strict document-level scopes and audience restrictions for mobile clients.',
      'Enforce high-fidelity API auditing with source application attribution.',
      'Throttle and alert on atypical bulk document retrieval patterns.',
    ],
  },
  ihe_xca: {
    security_features: ['Cross-community query/retrieve interoperability for clinical documents', 'Enables federated document access across independent trust domains'],
    known_weaknesses: [
      'Cross-domain trust misalignment can permit unauthorized community traversal',
      'Endpoint trust drift can silently weaken document-retrieval assurance',
    ],
    recommended_controls: ['SCF-IAM', 'SCF-AC', 'SCF-SCRM', 'SCF-AU'],
    configuration_guidance: [
      'Harden community trust anchors and certificate lifecycle management.',
      'Use explicit policy enforcement for query scope and permitted endpoints.',
      'Correlate cross-community transactions with patient and purpose-of-use context.',
    ],
  },
  ihe_xcpd: {
    security_features: ['Standardized cross-community patient discovery workflow', 'Supports identity correlation before document exchange'],
    known_weaknesses: [
      'Low-confidence matching can cause wrong-patient linkage and disclosure',
      'Demographic-query abuse may facilitate high-volume patient enumeration',
    ],
    recommended_controls: ['SCF-IAM', 'SCF-AC', 'SCF-AU', 'SCF-GOV'],
    configuration_guidance: [
      'Enforce confidence thresholds and manual review for ambiguous matches.',
      'Monitor demographic-query velocity and collision-prone attribute patterns.',
      'Preserve identity-provenance trails through downstream document retrieval workflows.',
    ],
  },
  ihe_pixm: {
    security_features: ['Mobile-friendly patient identifier cross-reference service', 'Improves identifier correlation consistency across source systems'],
    known_weaknesses: [
      'Identifier mapping drift can produce unsafe cross-record joins',
      'Weak access governance may expose broad identity-correlation datasets',
    ],
    recommended_controls: ['SCF-IAM', 'SCF-AC', 'SCF-AU'],
    configuration_guidance: [
      'Use least-privilege access for identifier cross-reference endpoints.',
      'Track and review high-risk mapping changes with dual-approval controls.',
      'Continuously reconcile identifier links with authoritative master-patient indexes.',
    ],
  },
  ihe_pdqm: {
    security_features: ['Modern demographics query profile for patient lookup', 'Supports search-based patient discovery with standardized semantics'],
    known_weaknesses: [
      'Over-broad query criteria can facilitate patient enumeration',
      'Inadequate query controls may leak high-sensitivity demographic attributes',
    ],
    recommended_controls: ['SCF-AC', 'SCF-IAM', 'SCF-AU', 'SCF-DLP'],
    configuration_guidance: [
      'Limit query fields and response payloads to minimum necessary data.',
      'Apply abuse-detection controls for repeated broad demographic searches.',
      'Bind query access to explicit purpose-of-use and role context.',
    ],
  },
  openehr: {
    security_features: ['Archetype/template-driven longitudinal clinical data modeling', 'Fine-grained semantic data structures for interoperable EHR workflows'],
    known_weaknesses: [
      'Overly broad archetype access can expose high-sensitivity clinical elements',
      'Template/version drift can weaken integrity assurance and audit traceability',
    ],
    recommended_controls: ['SCF-AC', 'SCF-AU', 'SCF-IAM', 'SCF-GOV'],
    configuration_guidance: [
      'Apply role- and purpose-based access constraints at archetype/template granularity.',
      'Control and audit template lifecycle/version changes with formal governance workflows.',
      'Validate semantic interoperability mappings before cross-system exchange at scale.',
    ],
  },
  hl7_cda_ccda: {
    security_features: ['Structured clinical document exchange with well-defined section semantics', 'Widely deployed in transitions-of-care and summary workflows'],
    known_weaknesses: [
      'Malformed or malicious document payloads can bypass weak semantic validation',
      'Document provenance and signature checks are inconsistently enforced',
    ],
    recommended_controls: ['SCF-SC', 'SCF-AU', 'SCF-IAM', 'SCF-IR'],
    configuration_guidance: [
      'Enforce digital signature and sender-trust validation for inbound documents.',
      'Combine schema checks with semantic plausibility validation before ingestion.',
      'Quarantine anomalous documents and require clinical review for high-risk sections.',
    ],
  },
  udap: {
    security_features: ['Healthcare trust framework for OAuth client onboarding and identity', 'Profiles for dynamic client registration and trust anchors'],
    known_weaknesses: [
      'Trust-anchor misconfiguration can authorize rogue client registrations',
      'Inadequate onboarding policy controls may grant excessive client scopes',
    ],
    recommended_controls: ['SCF-IAM', 'SCF-AC', 'SCF-SCRM', 'SCF-AU'],
    configuration_guidance: [
      'Govern trust anchors with formal issuance, rotation, and revocation workflows.',
      'Require attested onboarding checks and explicit scope approval policy.',
      'Monitor post-registration access behavior and enforce rapid quarantine on anomalies.',
    ],
  },
  direct_project: {
    security_features: ['Trusted message-based transport for clinical information exchange', 'Operationally established secure-routing ecosystem in many care networks'],
    known_weaknesses: [
      'Compromised sender domains can deliver malicious clinical payloads',
      'Transport trust alone does not guarantee document semantic integrity',
    ],
    recommended_controls: ['SCF-IAM', 'SCF-SC', 'SCF-AU'],
    configuration_guidance: [
      'Validate sender trust and certificate status continuously.',
      'Pair transport trust with payload signature and content validation controls.',
      'Audit and alert on unusual document exchange partners and payload characteristics.',
    ],
  },
  ihe_pcd: {
    security_features: ['Standardized patient care device data integration profiles', 'Supports interoperability between bedside systems and clinical records'],
    known_weaknesses: [
      'Vendor profile drift can produce unsafe interpretation of device telemetry',
      'Weak network segregation allows device data channels to be hijacked or replayed',
    ],
    recommended_controls: ['SCF-SC', 'SCF-AU', 'SCF-IAM', 'IEC_80001_SEGMENTATION'],
    configuration_guidance: [
      'Validate vendor conformance for required IHE PCD profiles before production use.',
      'Segment device integration brokers and enforce authenticated telemetry sessions.',
      'Correlate device event streams with patient context and alarm integrity checks.',
    ],
  },
  ieee_11073_sdc: {
    security_features: [
      'Service-oriented device connectivity for command/control and context sharing',
      'Supports interoperable device orchestration in acute care environments',
    ],
    known_weaknesses: [
      'Improper service trust configuration can allow unauthorized control-plane commands',
      'Context synchronization failures can create clinical safety and integrity hazards',
    ],
    recommended_controls: ['SCF-IAM', 'SCF-AC', 'SCF-SC', 'SCF-AU'],
    configuration_guidance: [
      'Use strong mutual authentication and certificate governance between devices and orchestrators.',
      'Apply explicit authorization policies for command invocations and role contexts.',
      'Continuously validate device context consistency and command provenance.',
    ],
  },
  ieee_11073_phd: {
    security_features: [
      'Interoperability for personal and remote monitoring health devices',
      'Supports home-care and chronic-care telemetry ingestion',
    ],
    known_weaknesses: [
      'Consumer network conditions and unmanaged endpoints increase interception risk',
      'Device identity spoofing can inject false observations into clinical pipelines',
    ],
    recommended_controls: ['SCF-IAM', 'SCF-DLP', 'SCF-SC', 'SCF-AU'],
    configuration_guidance: [
      'Bind telemetry to verifiable device identities and enrollment workflows.',
      'Use secure transport with integrity checks from edge device to ingestion API.',
      'Apply anomaly detection for out-of-profile vitals and source mismatch events.',
    ],
  },
  x12_005010: {
    security_features: ['Mature healthcare EDI transaction model for claims and eligibility', 'Operationally established in payer-provider exchange ecosystems'],
    known_weaknesses: [
      'Batch-based workflows can delay fraud and leakage detection',
      'Clearinghouse trust assumptions may mask partner-side compromise paths',
    ],
    recommended_controls: ['SCF-SCRM', 'SCF-AU', 'SCF-IAM', 'SCF-DLP'],
    configuration_guidance: [
      'Apply sender validation, partner allow-lists, and strict file integrity checks.',
      'Encrypt EDI payloads in transit and at rest across clearinghouse boundaries.',
      'Monitor transaction anomalies (volume, claim pattern, recipient drift).',
    ],
  },
  ncpdp_script: {
    security_features: ['Standardized e-prescribing transactions and refill workflows', 'Supports medication lifecycle exchange among providers and pharmacies'],
    known_weaknesses: [
      'Weak prescriber authentication controls can enable medication fraud',
      'Inadequate message integrity validation may alter dose or dispense instructions',
    ],
    recommended_controls: ['SCF-IAM', 'SCF-AC', 'SCF-AU', 'SCF-SC'],
    configuration_guidance: [
      'Require multifactor prescriber identity assurance in signing workflows.',
      'Validate medication order integrity end-to-end across intermediaries.',
      'Alert on unusual controlled-substance refill and destination patterns.',
    ],
  },
  spdx: {
    security_features: ['Machine-readable SBOM representation for component transparency', 'Supports dependency and license traceability in software supply chains'],
    known_weaknesses: [
      'Incomplete SBOM generation can create false confidence in dependency coverage',
      'Lack of update cadence can leave known vulnerable components untracked',
    ],
    recommended_controls: ['SCF-SCRM', 'SCF-SDLC', 'SCF-VM'],
    configuration_guidance: [
      'Generate SBOM artifacts in CI for all build variants and signed releases.',
      'Track component lineage to runtime deployment and patch status.',
      'Define freshness SLAs and attestation checks for SBOM completeness.',
    ],
  },
  cyclonedx: {
    security_features: ['SBOM format with rich vulnerability and dependency context', 'Supports operational integration with vulnerability management tooling'],
    known_weaknesses: [
      'Tooling mismatch between producers and consumers can drop critical metadata',
      'Unvalidated component identifiers can break accurate vulnerability matching',
    ],
    recommended_controls: ['SCF-SCRM', 'SCF-VM', 'SCF-SDLC'],
    configuration_guidance: [
      'Standardize CycloneDX schema versions across vendors and internal teams.',
      'Validate package identifiers and component hashes before ingestion.',
      'Link SBOM entries to remediation tickets and closure evidence.',
    ],
  },
  csaf_2_0: {
    security_features: ['Structured advisory exchange for vulnerability notifications', 'Automates supplier-to-operator vulnerability intelligence workflows'],
    known_weaknesses: [
      'Inconsistent product identifiers can prevent accurate impact determination',
      'Missing distribution authentication can allow advisory spoofing',
    ],
    recommended_controls: ['SCF-SCRM', 'SCF-IR', 'SCF-AU'],
    configuration_guidance: [
      'Normalize product IDs and CPE/PURL mappings before advisory correlation.',
      'Verify advisory authenticity and source trust chains on ingestion.',
      'Automate prioritization by exploitability and clinical criticality context.',
    ],
  },
  vex: {
    security_features: ['Machine-readable exploitability assertions for known vulnerabilities', 'Reduces patch noise by clarifying non-exploitable components'],
    known_weaknesses: [
      'Unsubstantiated non-exploitable claims can delay critical remediations',
      'Context drift between product versions can invalidate prior VEX assertions',
    ],
    recommended_controls: ['SCF-VM', 'SCF-SCRM', 'SCF-AU'],
    configuration_guidance: [
      'Require evidence-backed VEX status decisions and sign-off workflow.',
      'Re-evaluate VEX assertions on architecture, configuration, or version change.',
      'Correlate VEX claims with compensating controls and penetration findings.',
    ],
  },
};

export function getProtocolSecurity(args: unknown): Record<string, unknown> | ToolError {
  const input = (args ?? {}) as { protocol?: string };

  if (!input.protocol) {
    return {
      error: 'protocol is required',
      hint:
        'Use HL7v2/FHIR/SMART/UDAP/CDA, DICOM/DICOMWEB, IHE profiles (ATNA/XUA/IUA/SeR/XDS/MHD/XCA/XCPD/PIXm/PDQm/PCD), openEHR, IEEE_11073_SDC/PHD, X12_005010, NCPDP_SCRIPT, SPDX/CYCLONEDX/CSAF/VEX.',
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
    smart_backend_services: 'smart_backend_services',
    smart_backend: 'smart_backend_services',
    fhir_bulk_data: 'fhir_bulk_data',
    bulk_fhir: 'fhir_bulk_data',
    flat_fhir: 'fhir_bulk_data',
    dicom: 'dicom',
    dicomweb: 'dicomweb',
    dicom_web: 'dicomweb',
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
    xds: 'ihe_xds',
    ihe_xds: 'ihe_xds',
    mhd: 'ihe_mhd',
    ihe_mhd: 'ihe_mhd',
    xca: 'ihe_xca',
    ihe_xca: 'ihe_xca',
    xcpd: 'ihe_xcpd',
    ihe_xcpd: 'ihe_xcpd',
    pixm: 'ihe_pixm',
    ihe_pixm: 'ihe_pixm',
    pdqm: 'ihe_pdqm',
    ihe_pdqm: 'ihe_pdqm',
    openehr: 'openehr',
    hl7_cda_ccda: 'hl7_cda_ccda',
    hl7_cda: 'hl7_cda_ccda',
    ccda: 'hl7_cda_ccda',
    c_cda: 'hl7_cda_ccda',
    cda: 'hl7_cda_ccda',
    udap: 'udap',
    direct: 'direct_project',
    direct_project: 'direct_project',
    pcd: 'ihe_pcd',
    ihe_pcd: 'ihe_pcd',
    ieee_11073_sdc: 'ieee_11073_sdc',
    sdc: 'ieee_11073_sdc',
    ieee_11073_phd: 'ieee_11073_phd',
    phd: 'ieee_11073_phd',
    x12: 'x12_005010',
    x12_005010: 'x12_005010',
    x12_837: 'x12_005010',
    ncpdp: 'ncpdp_script',
    ncpdp_script: 'ncpdp_script',
    spdx: 'spdx',
    cyclonedx: 'cyclonedx',
    csaf: 'csaf_2_0',
    csaf_2_0: 'csaf_2_0',
    vex: 'vex',
  };

  const key = aliasMap[normalized];
  if (!key || !PROFILES[key]) {
    return {
      error: `Unsupported protocol: ${input.protocol}`,
      hint:
        'Supported protocols: HL7v2, FHIR, FHIR_R4, FHIR_R5, HL7_CDA_CCDA, SMART_ON_FHIR, SMART_BACKEND_SERVICES, FHIR_BULK_DATA, UDAP, DICOM, DICOMWEB, IHE, ATNA, XUA, IUA, SeR, XDS, MHD, XCA, XCPD, PIXm, PDQm, IHE_PCD, openEHR, IEEE_11073_SDC, IEEE_11073_PHD, X12_005010, NCPDP_SCRIPT, DIRECT_PROJECT, SPDX, CYCLONEDX, CSAF_2_0, VEX.',
    };
  }

  return {
    protocol: input.protocol,
    ...PROFILES[key],
  };
}
