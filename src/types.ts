export type JsonObject = Record<string, unknown>;

export interface AboutContext {
  version: string;
  fingerprint: string;
  dbBuilt: string;
}

export interface ToolError {
  error: string;
  hint?: string;
}

export interface ClassifyHealthDataInput {
  description: string;
  jurisdictions?: string[];
}

export interface ClassifyMedicalDeviceInput {
  description: string;
  region?: 'US' | 'EU' | 'US_EU';
}

export interface GetArchitecturePatternInput {
  pattern_id?: string;
  system_type?: string;
}

export interface GetHealthcareThreatsInput {
  pattern_id?: string;
  data_categories?: string[];
  query?: string;
  limit?: number;
  include_playbooks?: boolean;
}

export interface AssessHealthcareApplicabilityInput {
  organization_profile: {
    jurisdictions: string[];
    entity_type: string;
    data_categories: string[];
    has_medical_devices?: boolean;
    uses_ai_for_clinical_decisions?: boolean;
  };
}

export interface MapToHealthcareStandardsInput {
  input_type: 'threat' | 'architecture_pattern' | 'requirement' | 'control';
  input_id: string;
}

export interface AssessBreachObligationsInput {
  jurisdictions: string[];
  data_categories: string[];
  incident_summary: string;
}

export interface BuildHealthcareBaselineInput {
  organization_profile: {
    jurisdictions: string[];
    entity_type: string;
    data_categories: string[];
    architecture_patterns?: string[];
    has_medical_devices?: boolean;
  };
}

export interface BuildEvidencePlanInput {
  audit_type?: string;
  baseline_control_ids?: string[];
  threat_ids?: string[];
  include_threat_appendix?: boolean;
}

export interface CompareJurisdictionsInput {
  topic: string;
  jurisdictions: string[];
  resolve_authoritative?: boolean;
  max_upstreams?: number;
}

export interface ResolveAuthoritativeContextInput {
  topic: string;
  route_refs?: string[];
  jurisdictions?: string[];
  max_upstreams?: number;
  max_tool_attempts?: number;
}
