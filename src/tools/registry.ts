import type { SqlDatabase } from '../db.js';
import type { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolRequest,
  type CallToolResult,
} from '@modelcontextprotocol/sdk/types.js';
import { getAbout } from './about.js';
import { listSources } from './list_sources.js';
import { listArchitecturePatterns } from './list_architecture_patterns.js';
import { listProfiles } from './list_profiles.js';
import { classifyHealthData } from './classify_health_data.js';
import { classifyMedicalDevice } from './classify_medical_device.js';
import { getArchitecturePattern } from './get_architecture_pattern.js';
import { getHealthcareThreats } from './get_healthcare_threats.js';
import { assessHealthcareApplicability } from './assess_healthcare_applicability.js';
import { mapToHealthcareStandards } from './map_to_healthcare_standards.js';
import { searchDomainKnowledge } from './search_domain_knowledge.js';
import { assessBreachObligations } from './assess_breach_obligations.js';
import { buildHealthcareBaseline } from './build_healthcare_baseline.js';
import { buildEvidencePlan } from './build_evidence_plan.js';
import { compareJurisdictions } from './compare_jurisdictions.js';
import { resolveAuthoritativeContext } from './resolve_authoritative_context.js';
import { getProtocolSecurity } from './get_protocol_security.js';
import { assessClinicalRisk } from './assess_clinical_risk.js';
import { mapHipaaSafeguards } from './map_hipaa_safeguards.js';
import { createRemediationBacklog } from './create_remediation_backlog.js';
import { getThreatResponsePlaybook } from './get_threat_response_playbook.js';
import type { AboutContext } from '../types.js';

interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, unknown>;
    required?: string[];
    examples?: Array<Record<string, unknown>>;
  };
  handler: (db: SqlDatabase, args: unknown) => unknown | Promise<unknown>;
}

type SchemaNode = {
  type?: string;
  enum?: unknown[];
  default?: unknown;
  minimum?: number;
  properties?: Record<string, SchemaNode>;
  required?: string[];
  items?: SchemaNode;
};

const TOOL_EXAMPLES: Record<string, Array<Record<string, unknown>>> = {
  about: [{}],
  list_sources: [{ source_type: 'regulation_index' }],
  list_architecture_patterns: [{ category: 'EHR' }],
  list_profiles: [{ profile_type: 'jurisdiction_overlays' }],
  classify_data: [
    {
      description: 'Hospital EHR stores diagnoses, lab panels, and genetic reports for US and EU clinics.',
      jurisdictions: ['US', 'EU'],
    },
  ],
  classify_health_data: [
    {
      description: 'Behavioral health platform stores mental-health notes and substance-use treatment history.',
      jurisdictions: ['US-CA'],
    },
  ],
  classify_medical_device: [
    {
      description: 'Cloud-connected infusion pump software adjusts dosage using predictive analytics.',
      region: 'US_EU',
      data_types: ['ephi', 'device_telemetry'],
    },
  ],
  get_architecture_pattern: [{ pattern_id: 'hc-ehr' }],
  get_domain_threats: [{ pattern_id: 'hc-ehr', include_playbooks: true, limit: 5 }],
  get_healthcare_threats: [{ pattern_id: 'hc-ehr', include_playbooks: true, detail_level: 'standard', limit: 5 }],
  get_threat_response_playbook: [{ threat_id: 'th_hl7_fhir_token_theft' }],
  assess_healthcare_applicability: [
    {
      country: 'US-CA,DE',
      role: 'provider',
      system_types: ['ehr', 'medical_device'],
      data_types: ['ephi', 'genetic_data'],
      detail_level: 'standard',
      additional_context: {
        has_medical_devices: true,
        uses_ai_for_clinical_decisions: true,
      },
    },
  ],
  assess_applicability: [
    {
      organization_profile: {
        jurisdictions: ['US-CA', 'DE'],
        entity_type: 'provider',
        data_categories: ['ephi', 'special_category_health_data'],
        has_medical_devices: true,
        uses_ai_for_clinical_decisions: true,
      },
      detail_level: 'summary',
    },
  ],
  map_to_technical_standards: [{ input_type: 'requirement', input_id: 'FDA_524B' }],
  map_to_healthcare_standards: [{ input_type: 'threat', input_id: 'th_iomt_ransomware_clinical_ops' }],
  search_domain_knowledge: [{ query: 'FHIR token theft', content_type: 'threat', limit: 5 }],
  assess_breach_obligations: [
    {
      jurisdictions: ['US', 'EU'],
      data_categories: ['ephi', 'special_category_health_data'],
      incident_summary: 'Unauthorized cloud export of patient and genetic records.',
    },
  ],
  build_healthcare_baseline: [
    {
      organization_profile: {
        jurisdictions: ['US-CA'],
        entity_type: 'provider',
        data_categories: ['ephi'],
        architecture_patterns: ['hc-ehr'],
        has_medical_devices: false,
      },
    },
  ],
  build_control_baseline: [
    {
      org_profile: {
        jurisdictions: ['DE'],
        entity_type: 'provider',
        data_categories: ['special_category_health_data'],
      },
    },
  ],
  build_evidence_plan: [
    {
      audit_type: 'MDR_IVDR',
      baseline_control_ids: ['FDA_524B_VULN_MGMT'],
      threat_ids: ['th_device_firmware_manipulation'],
    },
  ],
  create_remediation_backlog: [
    {
      current_state: { implemented_controls: ['AU-2'], known_gaps: ['Missing device SBOM workflow'] },
      target_baseline: { controls: [{ control_id: 'AC-6' }] },
    },
  ],
  compare_jurisdictions: [{ topic: 'breach notification', jurisdictions: ['US-CA', 'DE'] }],
  resolve_authoritative_context: [{ topic: 'HIPAA safeguards and GDPR Article 9', jurisdictions: ['US', 'EU'] }],
  get_protocol_security: [{ protocol: 'SMART on FHIR' }],
  assess_clinical_risk: [{ threat_scenario: 'Infusion pump command tampering in ICU', clinical_setting: 'ICU' }],
  map_hipaa_safeguards: [{ system_description: 'Cloud-hosted patient portal integrated with EHR', data_types: ['ephi'] }],
};

function buildSchemaExample(node: SchemaNode, keyHint = 'value'): unknown {
  if (node.default !== undefined) {
    return node.default;
  }
  if (Array.isArray(node.enum) && node.enum.length > 0) {
    return node.enum[0];
  }
  if (node.type === 'string') {
    return keyHint.includes('id') ? 'example_id' : 'example';
  }
  if (node.type === 'number' || node.type === 'integer') {
    return node.minimum ?? 1;
  }
  if (node.type === 'boolean') {
    return true;
  }
  if (node.type === 'array') {
    const item = node.items ? buildSchemaExample(node.items, keyHint) : 'example';
    return [item];
  }
  if (node.type === 'object') {
    const required = new Set(node.required ?? []);
    const properties = node.properties ?? {};
    const objectExample: Record<string, unknown> = {};
    for (const [childKey, childNode] of Object.entries(properties)) {
      if (required.size === 0 || required.has(childKey)) {
        objectExample[childKey] = buildSchemaExample(childNode, childKey);
      }
    }
    return objectExample;
  }
  return 'example';
}

function schemaWithExamples(toolName: string, schema: ToolDefinition['inputSchema']): ToolDefinition['inputSchema'] {
  if (Array.isArray(schema.examples) && schema.examples.length > 0) {
    return schema;
  }
  const explicit = TOOL_EXAMPLES[toolName];
  if (explicit && explicit.length > 0) {
    return { ...schema, examples: explicit };
  }
  return {
    ...schema,
    examples: [buildSchemaExample(schema as SchemaNode) as Record<string, unknown>],
  };
}

function dbMeta(db: SqlDatabase, key: string): string | null {
  const row = db
    .prepare('SELECT value FROM db_metadata WHERE key = ?')
    .get(key) as { value: string } | undefined;
  return row?.value ?? null;
}

function collectSourceRouters(value: unknown, out: Set<string>): void {
  if (!value) {
    return;
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      collectSourceRouters(item, out);
    }
    return;
  }

  if (typeof value !== 'object') {
    return;
  }

  const record = value as Record<string, unknown>;
  for (const [key, entry] of Object.entries(record)) {
    if (
      (key === 'source_router' || key === 'authoritative_route') &&
      typeof entry === 'string' &&
      entry.trim().length > 0
    ) {
      out.add(entry.trim());
    } else {
      collectSourceRouters(entry, out);
    }
  }
}

function routeStringToCalls(route: string): Array<Record<string, unknown>> {
  const calls: Array<Record<string, unknown>> = [];
  const parts = route.split('+').map((part) => part.trim()).filter(Boolean);
  for (const part of parts) {
    if (part.includes(':')) {
      const [mcp, ...rest] = part.split(':');
      calls.push({
        mcp,
        tool: 'lookup_reference',
        params: {
          ref: rest.join(':'),
        },
      });
      continue;
    }

    if (part.length > 0) {
      calls.push({
        mcp: part,
        tool: 'route',
        params: {},
      });
    }
  }
  return calls;
}

function deriveFoundationCalls(result: unknown): Array<Record<string, unknown>> {
  if (!result || typeof result !== 'object') {
    return [];
  }

  const payload = result as Record<string, unknown>;

  if (Array.isArray(payload.foundation_mcp_calls)) {
    return payload.foundation_mcp_calls as Array<Record<string, unknown>>;
  }

  const calls: Array<Record<string, unknown>> = [];

  if (Array.isArray(payload.router_calls_required)) {
    for (const route of payload.router_calls_required) {
      calls.push({
        mcp: String(route),
        tool: 'route',
        params: {},
      });
    }
  }

  if (Array.isArray(payload.routes)) {
    for (const route of payload.routes) {
      calls.push({
        mcp: String(route),
        tool: 'route',
        params: {},
      });
    }
  }

  if (Array.isArray(payload.upstream_results)) {
    for (const item of payload.upstream_results as Array<Record<string, unknown>>) {
      calls.push({
        mcp: String(item.label ?? item.kind ?? 'unknown'),
        tool: String(item.selected_tool ?? 'unknown'),
        params: {},
      });
    }
  }

  const routeSet = new Set<string>();
  collectSourceRouters(result, routeSet);
  for (const route of routeSet) {
    calls.push(...routeStringToCalls(route));
  }

  return Array.from(
    new Map(calls.map((call) => [`${String(call.mcp)}|${String(call.tool)}|${JSON.stringify(call.params)}`, call]))
      .values(),
  );
}

function normalizeCitationType(ref: string): 'CELEX' | 'CFR' | 'USC' | 'ISO' | 'IEC' | 'NIST' | null {
  if (/^(GDPR|NIS2|MDR|IVDR|AI_ACT|EHDS)/i.test(ref)) {
    return 'CELEX';
  }
  if (/^(HIPAA|HITECH|CCPA|CPRA|FDA_|42\s*CFR|CFR|PART2|CA_CMIA|NY_|TX_)/i.test(ref)) {
    return 'CFR';
  }
  if (/^USC/i.test(ref)) {
    return 'USC';
  }
  if (/^ISO_/i.test(ref)) {
    return 'ISO';
  }
  if (/^IEC_/i.test(ref)) {
    return 'IEC';
  }
  if (/^NIST_/i.test(ref)) {
    return 'NIST';
  }
  return null;
}

function sourceUrlForCitationType(type: 'CELEX' | 'CFR' | 'USC' | 'ISO' | 'IEC' | 'NIST'): string {
  switch (type) {
    case 'CELEX':
      return 'https://eur-lex.europa.eu/';
    case 'CFR':
      return 'https://www.ecfr.gov/';
    case 'USC':
      return 'https://uscode.house.gov/';
    case 'ISO':
      return 'https://www.iso.org/standards.html';
    case 'IEC':
      return 'https://www.iec.ch/standards';
    case 'NIST':
      return 'https://csrc.nist.gov/publications';
    default:
      return '';
  }
}

function collectReferenceStrings(value: unknown, out: Set<string>, currentKey?: string): void {
  if (!value) {
    return;
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      collectReferenceStrings(item, out, currentKey);
    }
    return;
  }

  if (typeof value === 'string') {
    const key = currentKey ?? '';
    if (
      key === 'regulation_refs' ||
      key === 'standard_refs' ||
      key === 'applicable_regimes' ||
      key === 'regulation_id' ||
      key === 'standard_id' ||
      key === 'requirement_ref'
    ) {
      out.add(value.trim());
    }
    return;
  }

  if (typeof value !== 'object') {
    return;
  }

  for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
    collectReferenceStrings(nested, out, key);
  }
}

function deriveCitations(result: unknown): Array<{ type: string; ref: string; source_url: string }> {
  const refs = new Set<string>();
  collectReferenceStrings(result, refs);

  const citations: Array<{ type: string; ref: string; source_url: string }> = [];
  for (const ref of refs) {
    if (!ref || ref === 'null') {
      continue;
    }
    const type = normalizeCitationType(ref);
    if (!type) {
      continue;
    }
    citations.push({
      type,
      ref,
      source_url: sourceUrlForCitationType(type),
    });
  }

  return citations.slice(0, 30);
}

function extractOutOfScope(result: unknown): string[] {
  if (!result || typeof result !== 'object') {
    return [];
  }

  const payload = result as Record<string, unknown>;
  const topLevel = payload.out_of_scope;
  if (Array.isArray(topLevel)) {
    return topLevel.map((item) => String(item));
  }

  const overlaySummary = payload.overlay_summary;
  if (overlaySummary && typeof overlaySummary === 'object') {
    const nested = (overlaySummary as Record<string, unknown>).out_of_scope;
    if (Array.isArray(nested)) {
      return nested.map((item) => String(item));
    }
  }

  return [];
}

function wrapWithMetadata(
  db: SqlDatabase,
  context: AboutContext,
  toolName: string,
  result: unknown,
): Record<string, unknown> {
  const schemaVersion = dbMeta(db, 'schema_version') ?? context.version;
  const lastSourceCheck = dbMeta(db, 'last_source_check') ?? context.dbBuilt;

  const hasAuthoritativeContext =
    toolName === 'resolve_authoritative_context' ||
    (result &&
      typeof result === 'object' &&
      'authoritative_context' in (result as Record<string, unknown>));

  const payloadConfidence =
    result &&
    typeof result === 'object' &&
    typeof (result as Record<string, unknown>).confidence === 'string'
      ? String((result as Record<string, unknown>).confidence)
      : null;

  const confidence = hasAuthoritativeContext
    ? 'authoritative'
    : payloadConfidence === 'authoritative' || payloadConfidence === 'estimated'
      ? payloadConfidence
      : 'inferred';

  return {
    data: result,
    metadata: {
      citations: deriveCitations(result),
      effective_date: lastSourceCheck,
      confidence,
      inference_rationale:
        confidence === 'authoritative'
          ? 'Includes runtime retrieval from configured upstream foundation MCP endpoints.'
          : 'Derived from healthcare domain taxonomy, threat catalog, and crosswalk logic in this MCP.',
      last_verified: lastSourceCheck,
      dataset_version: schemaVersion,
      dataset_fingerprint: `sha256:${context.fingerprint}`,
      out_of_scope: extractOutOfScope(result),
      foundation_mcp_calls: deriveFoundationCalls(result),
    },
  };
}

export function createToolDefinitions(context: AboutContext): ToolDefinition[] {
  return [
    {
      name: 'about',
      description:
        'Return server metadata, dataset counts, provenance posture, and MCP composition model. Use this first to verify freshness assumptions and understand what this MCP delegates to regulation/control MCPs.',
      inputSchema: {
        type: 'object',
        properties: {},
      },
      handler: (db) => getAbout(db, context),
    },
    {
      name: 'list_sources',
      description:
        'List authoritative sources and provenance metadata used by this domain MCP, including refresh cadence and licensing constraints.',
      inputSchema: {
        type: 'object',
        properties: {
          source_type: {
            type: 'string',
            description: 'Optional source type filter.',
          },
        },
      },
      handler: (db, args) => listSources(db, args),
    },
    {
      name: 'list_architecture_patterns',
      description:
        'List architecture pattern IDs and descriptions for healthcare system archetypes. Use this to discover valid pattern IDs before get_architecture_pattern.',
      inputSchema: {
        type: 'object',
        properties: {
          category: {
            type: 'string',
            description: 'Optional primary system category filter such as EHR or Imaging.',
          },
        },
      },
      handler: (db, args) => listArchitecturePatterns(db, args),
    },
    {
      name: 'list_profiles',
      description:
        'List ontology profiles available in this MCP: health data categories, architecture patterns, threat expert profiles, threat response playbooks, and obligation profiles. Use this when selecting valid IDs for downstream tools.',
      inputSchema: {
        type: 'object',
        properties: {
          profile_type: {
            type: 'string',
            enum: [
              'data_categories',
              'architecture_patterns',
              'threat_expert_profiles',
              'threat_response_playbooks',
              'obligation_profiles',
              'jurisdiction_overlays',
              'jurisdiction_coverage',
              'all',
            ],
            description: 'Optional filter to reduce output size. Default: all.',
          },
        },
      },
      handler: (db, args) => listProfiles(db, args),
    },
    {
      name: 'classify_data',
      description:
        'Universal alias for classify_health_data. Classifies healthcare data categories and protection tiers for the requested jurisdictions.',
      inputSchema: {
        type: 'object',
        properties: {
          description: {
            type: 'string',
            minLength: 8,
            description: 'Description of healthcare data processed.',
          },
          data_description: {
            type: 'string',
            minLength: 8,
            description: 'Spec-compatible alias for description.',
          },
          jurisdictions: {
            type: 'array',
            items: { type: 'string' },
            description: 'Optional jurisdiction hints such as ["US", "EU", "US-CA"] to prioritize regime inference.',
          },
        },
      },
      handler: (db, args) => classifyHealthData(db, args),
    },
    {
      name: 'classify_health_data',
      description:
        'Classify described healthcare data into sensitivity categories (ePHI, Part 2, genetic, operational) and infer likely US/EU regulatory regimes. Use this before threat severity and breach assessments.',
      inputSchema: {
        type: 'object',
        properties: {
          description: {
            type: 'string',
            description: 'Natural-language description of processed data, storage, and sharing behavior.',
            minLength: 8,
          },
          jurisdictions: {
            type: 'array',
            items: { type: 'string' },
            description: 'Optional region list such as ["US", "EU"].',
          },
        },
        required: ['description'],
      },
      handler: (db, args) => classifyHealthData(db, args),
    },
    {
      name: 'classify_medical_device',
      description:
        'Perform preliminary medical device/SaMD classification routing based on intended use signals. Returns likely FDA/MDR class direction and required standards pathways, not legal final determination.',
      inputSchema: {
        type: 'object',
        properties: {
          description: {
            type: 'string',
            description: 'Describe product function, patient impact, and whether outputs affect diagnosis or therapy.',
            minLength: 10,
          },
          device_description: {
            type: 'string',
            description: 'Spec-compatible device description field.',
          },
          software_function: {
            type: 'string',
            description: 'Software function description for SaMD determination.',
          },
          clinical_purpose: {
            type: 'string',
            description: 'Clinical purpose statement.',
          },
          data_types: {
            type: 'array',
            items: { type: 'string' },
            description: 'Data types processed by the device/software.',
          },
          region: {
            type: 'string',
            enum: ['US', 'EU', 'US_EU'],
            description: 'Regulatory lens for classification heuristics. Default: US_EU.',
          },
        },
      },
      handler: (db, args) => classifyMedicalDevice(db, args),
    },
    {
      name: 'get_architecture_pattern',
      description:
        'Retrieve canonical healthcare architecture pattern with components, trust boundaries, data flows, and known weak points. Use this to generate architecture-aware threat modeling scenarios.',
      inputSchema: {
        type: 'object',
        properties: {
          pattern_id: {
            type: 'string',
            description: 'Exact pattern ID from list_profiles.',
          },
          system_type: {
            type: 'string',
            description: 'Fallback system type selector, such as EHR or Imaging.',
          },
        },
      },
      handler: (db, args) => getArchitecturePattern(db, args),
    },
    {
      name: 'get_domain_threats',
      description:
        'Universal alias for get_healthcare_threats. Returns domain threat scenarios with MITRE mapping, operational response playbook guidance, and regulatory/control links.',
      inputSchema: {
        type: 'object',
        properties: {
          pattern_id: {
            type: 'string',
            description: 'Optional architecture pattern ID from list_architecture_patterns.',
          },
          architecture_pattern: {
            type: 'string',
            description: 'Spec-compatible alias for pattern_id.',
          },
          data_categories: {
            type: 'array',
            items: { type: 'string' },
            description: 'Optional healthcare data-category IDs to tighten relevance scoring.',
          },
          data_types: {
            type: 'array',
            items: { type: 'string' },
            description: 'Spec-compatible alias for data_categories.',
          },
          deployment_context: {
            type: 'string',
            description: 'Optional context like cloud_hospital, hybrid_hie, or on_prem_device_network.',
          },
          query: {
            type: 'string',
            description: 'Optional keyword filter over threat names and descriptions.',
          },
          include_playbooks: {
            type: 'boolean',
            description: 'When true, include operational response playbook actions in each threat record.',
            default: true,
          },
          detail_level: {
            type: 'string',
            enum: ['summary', 'standard', 'full'],
            description: 'Controls response verbosity. Use summary for token-constrained flows.',
            default: 'full',
          },
          cursor: {
            type: 'string',
            description: 'Opaque pagination cursor from a prior get_domain_threats response.',
          },
          limit: {
            type: 'number',
            minimum: 1,
            maximum: 50,
            description: 'Maximum results returned. Default: 10.',
            default: 10,
          },
        },
      },
      handler: (db, args) => getHealthcareThreats(db, args),
    },
    {
      name: 'get_healthcare_threats',
      description:
        'Return healthcare-specific threat scenarios with clinical impact context, MITRE tactics, and route links to regulation/control MCP identifiers. Supports FTS search, pattern filtering, and capped result sets.',
      inputSchema: {
        type: 'object',
        properties: {
          pattern_id: {
            type: 'string',
            description: 'Optional architecture pattern filter.',
          },
          data_categories: {
            type: 'array',
            items: { type: 'string' },
            description: 'Optional data category IDs to narrow threat relevance.',
          },
          query: {
            type: 'string',
            description: 'Optional FTS keyword query. Do not use raw SQL/FTS syntax.',
          },
          include_playbooks: {
            type: 'boolean',
            description:
              'Include threat-specific containment/clinical-safety/forensic/recovery playbook guidance. Default: true.',
          },
          detail_level: {
            type: 'string',
            enum: ['summary', 'standard', 'full'],
            description: 'Controls response verbosity. Use summary for token-constrained flows.',
            default: 'full',
          },
          cursor: {
            type: 'string',
            description: 'Opaque pagination cursor from a prior get_healthcare_threats response.',
          },
          limit: {
            type: 'number',
            minimum: 1,
            maximum: 50,
            description: 'Maximum number of threats. Default: 10.',
          },
        },
      },
      handler: (db, args) => getHealthcareThreats(db, args),
    },
    {
      name: 'get_threat_response_playbook',
      description:
        'Retrieve operational response playbook for a healthcare threat ID, including containment, clinical safety, forensic, recovery, and communication actions.',
      inputSchema: {
        type: 'object',
        properties: {
          threat_id: {
            type: 'string',
            description: 'Threat ID from get_healthcare_threats.',
            minLength: 3,
          },
        },
        required: ['threat_id'],
      },
      handler: (db, args) => getThreatResponsePlaybook(db, args),
    },
    {
      name: 'assess_healthcare_applicability',
      description:
        'Assess healthcare compliance applicability from organization profile and return prioritized obligation routes to specialized MCPs, including strictest-wins conflict resolution for overlapping obligations. Use this as the main domain-router step before control and legal deep dives.',
      inputSchema: {
        type: 'object',
        properties: {
          organization_profile: {
            type: 'object',
            properties: {
              jurisdictions: {
                type: 'array',
                items: { type: 'string' },
                description: 'Jurisdictions where processing occurs, e.g., ["US-CA", "DE"].',
              },
              entity_type: {
                type: 'string',
                description: 'Healthcare role such as provider, payer, medtech_vendor, or processor.',
              },
              data_categories: {
                type: 'array',
                items: { type: 'string' },
                description: 'Healthcare data categories such as ephi, genetic_data, part2_substance_use.',
              },
              has_medical_devices: {
                type: 'boolean',
                description: 'Set true when networked/clinical devices are in scope.',
              },
              uses_ai_for_clinical_decisions: {
                type: 'boolean',
                description: 'Set true when AI outputs influence diagnosis, triage, or therapy.',
              },
            },
            required: ['jurisdictions', 'entity_type', 'data_categories'],
            description: 'Operational profile for applicability resolution.',
          },
          country: {
            type: 'string',
            description: 'Convenience shorthand when providing a single country/state code.',
          },
          role: {
            type: 'string',
            description: 'Alias for entity type when organization_profile is not supplied.',
          },
          system_types: {
            type: 'array',
            items: { type: 'string' },
            description: 'System archetypes such as ehr, telehealth, pacs, medical_device.',
          },
          data_types: {
            type: 'array',
            items: { type: 'string' },
            description: 'Alias for data_categories.',
          },
          additional_context: {
            type: 'object',
            description: 'Optional feature flags and jurisdiction hints that affect overlay matching.',
            properties: {
              has_medical_devices: {
                type: 'boolean',
                description: 'Overrides device scope signal during overlay selection.',
              },
              uses_ai_for_clinical_decisions: {
                type: 'boolean',
                description: 'Overrides clinical AI signal during overlay selection.',
              },
              jurisdictions: {
                type: 'array',
                items: { type: 'string' },
                description: 'Additional jurisdictions to merge into evaluation scope.',
              },
              country_codes: {
                type: 'array',
                items: { type: 'string' },
                description: 'Alternative country/state code list for compatibility integrations.',
              },
            },
          },
          detail_level: {
            type: 'string',
            enum: ['summary', 'standard', 'full'],
            description: 'Controls response verbosity. Use summary for orchestration routing steps.',
            default: 'full',
          },
        },
      },
      handler: (db, args) => assessHealthcareApplicability(db, args),
    },
    {
      name: 'assess_applicability',
      description:
        'Universal alias for assess_healthcare_applicability. Builds obligation map for an organization profile with foundation MCP routing guidance and deterministic strictest-wins conflict output.',
      inputSchema: {
        type: 'object',
        properties: {
          organization_profile: {
            type: 'object',
            description: 'Primary profile object for determining healthcare applicability obligations.',
            properties: {
              jurisdictions: {
                type: 'array',
                items: { type: 'string' },
                description: 'Jurisdictions where processing occurs, e.g., ["US-CA", "DE"].',
              },
              entity_type: {
                type: 'string',
                description: 'Healthcare role such as provider, payer, medtech_vendor, or processor.',
              },
              data_categories: {
                type: 'array',
                items: { type: 'string' },
                description: 'Healthcare data categories such as ephi, genetic_data, part2_substance_use.',
              },
              has_medical_devices: {
                type: 'boolean',
                description: 'Set true when networked/clinical devices are in scope.',
              },
              uses_ai_for_clinical_decisions: {
                type: 'boolean',
                description: 'Set true when AI outputs influence diagnosis, triage, or therapy.',
              },
            },
            required: ['jurisdictions', 'entity_type', 'data_categories'],
          },
          country: {
            type: 'string',
            description: 'Convenience shorthand when providing a single country/state code.',
          },
          role: {
            type: 'string',
            description: 'Alias for entity type when organization_profile is not supplied.',
          },
          system_types: {
            type: 'array',
            items: { type: 'string' },
            description: 'System archetypes such as ehr, telehealth, pacs, medical_device.',
          },
          data_types: {
            type: 'array',
            items: { type: 'string' },
            description: 'Alias for data_categories.',
          },
          additional_context: {
            type: 'object',
            description: 'Optional feature flags and jurisdiction hints that affect overlay matching.',
            properties: {
              has_medical_devices: {
                type: 'boolean',
                description: 'Overrides device scope signal during overlay selection.',
              },
              uses_ai_for_clinical_decisions: {
                type: 'boolean',
                description: 'Overrides clinical AI signal during overlay selection.',
              },
              jurisdictions: {
                type: 'array',
                items: { type: 'string' },
                description: 'Additional jurisdictions to merge into evaluation scope.',
              },
              country_codes: {
                type: 'array',
                items: { type: 'string' },
                description: 'Alternative country/state code list for compatibility integrations.',
              },
            },
          },
          detail_level: {
            type: 'string',
            enum: ['summary', 'standard', 'full'],
            description: 'Controls response verbosity. Use summary for orchestration routing steps.',
            default: 'full',
          },
        },
      },
      handler: (db, args) => assessHealthcareApplicability(db, args),
    },
    {
      name: 'map_to_technical_standards',
      description:
        'Universal alias for map_to_healthcare_standards. Maps requirements, controls, threats, or patterns to healthcare-relevant standards.',
      inputSchema: {
        type: 'object',
        properties: {
          input_type: {
            type: 'string',
            enum: ['threat', 'architecture_pattern', 'requirement', 'control'],
            description: 'Type of object being mapped to healthcare standards.',
          },
          input_id: {
            type: 'string',
            minLength: 1,
            description: 'Identifier value for the selected input_type.',
          },
          requirement_ref: {
            type: 'string',
            description: 'Spec-compatible requirement reference input.',
          },
          control_id: {
            type: 'string',
            description: 'Spec-compatible control ID input.',
          },
        },
      },
      handler: (db, args) => mapToHealthcareStandards(db, args),
    },
    {
      name: 'map_to_healthcare_standards',
      description:
        'Map threat, architecture, requirement, or control IDs to healthcare technical standards (IEC 62304, ISO 14971, IEC 80001-1, IEC 81001-5-1, IEEE 11073, FHIR/IHE, SBOM and vuln exchange) with rationale.',
      inputSchema: {
        type: 'object',
        properties: {
          input_type: {
            type: 'string',
            enum: ['threat', 'architecture_pattern', 'requirement', 'control'],
            description: 'Type of object being mapped to healthcare standards.',
          },
          input_id: {
            type: 'string',
            description: 'Identifier from upstream output.',
            minLength: 1,
          },
        },
        required: ['input_type', 'input_id'],
      },
      handler: (db, args) => mapToHealthcareStandards(db, args),
    },
    {
      name: 'search_domain_knowledge',
      description:
        'Search healthcare domain knowledge across threat catalog, architecture patterns, and technical standards with token-safe result limits.',
      inputSchema: {
        type: 'object',
        properties: {
          query: {
            type: 'string',
            minLength: 2,
            description: 'Search query.',
          },
          content_type: {
            type: 'string',
            enum: ['threat', 'architecture', 'standards', 'all'],
            description: 'Optional content filter. Default: all.',
          },
          limit: {
            type: 'number',
            minimum: 1,
            maximum: 50,
            description: 'Maximum results. Default: 10.',
          },
          cursor: {
            type: 'string',
            description: 'Opaque pagination cursor from a prior search_domain_knowledge response.',
          },
        },
        required: ['query'],
      },
      handler: (db, args) => searchDomainKnowledge(db, args),
    },
    {
      name: 'assess_breach_obligations',
      description:
        'Generate healthcare breach-notification timeline candidates by jurisdiction and data category. Returns strictest deadline view and required notification content fields.',
      inputSchema: {
        type: 'object',
        properties: {
          jurisdictions: {
            type: 'array',
            items: { type: 'string' },
            description: 'Jurisdictions to evaluate for breach-notification obligations.',
          },
          data_categories: {
            type: 'array',
            items: { type: 'string' },
            description: 'Healthcare data categories implicated by the incident.',
          },
          data_types: {
            type: 'array',
            items: { type: 'string' },
            description: 'Spec-compatible alias for data_categories.',
          },
          incident_summary: {
            type: 'string',
            minLength: 8,
            description: 'High-level incident context for escalation logic.',
          },
          incident_description: {
            type: 'string',
            minLength: 8,
            description: 'Spec-compatible alias for incident_summary.',
          },
        },
        required: ['jurisdictions'],
      },
      handler: (db, args) => assessBreachObligations(db, args),
    },
    {
      name: 'build_healthcare_baseline',
      description:
        'Build a prioritized healthcare security baseline from organization context, emphasizing clinically relevant control outcomes and device-specific controls where applicable.',
      inputSchema: {
        type: 'object',
        properties: {
          organization_profile: {
            type: 'object',
            description: 'Organization context used to prioritize baseline controls.',
            properties: {
              jurisdictions: {
                type: 'array',
                items: { type: 'string' },
                description: 'Jurisdictions where systems/processes are operated.',
              },
              entity_type: {
                type: 'string',
                description: 'Healthcare role such as provider, payer, medtech_vendor, or processor.',
              },
              data_categories: {
                type: 'array',
                items: { type: 'string' },
                description: 'Healthcare data categories in scope for baseline design.',
              },
              architecture_patterns: {
                type: 'array',
                items: { type: 'string' },
                description: 'Optional architecture pattern IDs from list_architecture_patterns.',
              },
              has_medical_devices: {
                type: 'boolean',
                description: 'Set true to prioritize device-network and product-security controls.',
              },
            },
            required: ['jurisdictions', 'entity_type', 'data_categories'],
          },
          org_profile: {
            type: 'object',
            description: 'Spec-compatible alias for organization_profile.',
          },
        },
      },
      handler: (db, args) => buildHealthcareBaseline(db, args),
    },
    {
      name: 'build_control_baseline',
      description:
        'Universal alias for build_healthcare_baseline. Returns prioritized healthcare control baseline for organization context.',
      inputSchema: {
        type: 'object',
        properties: {
          organization_profile: {
            type: 'object',
            description: 'Organization context used to prioritize baseline controls.',
            properties: {
              jurisdictions: {
                type: 'array',
                items: { type: 'string' },
                description: 'Jurisdictions where systems/processes are operated.',
              },
              entity_type: {
                type: 'string',
                description: 'Healthcare role such as provider, payer, medtech_vendor, or processor.',
              },
              data_categories: {
                type: 'array',
                items: { type: 'string' },
                description: 'Healthcare data categories in scope for baseline design.',
              },
              architecture_patterns: {
                type: 'array',
                items: { type: 'string' },
                description: 'Optional architecture pattern IDs from list_architecture_patterns.',
              },
              has_medical_devices: {
                type: 'boolean',
                description: 'Set true to prioritize device-network and product-security controls.',
              },
            },
            required: ['jurisdictions', 'entity_type', 'data_categories'],
          },
          org_profile: {
            type: 'object',
            description: 'Spec-compatible alias for organization_profile.',
          },
        },
      },
      handler: (db, args) => buildHealthcareBaseline(db, args),
    },
    {
      name: 'build_evidence_plan',
      description:
        'Return audit-ready evidence artifacts and templates for healthcare audits (HIPAA, NIS2, FDA_524B, MDR/IVDR, AI Act, HITRUST, ISO 27001/27799, threat-response annexes). Supports integrating baseline controls and threat IDs to build incident-evidence checklists.',
      inputSchema: {
        type: 'object',
        properties: {
          audit_type: {
            type: 'string',
            description:
              'Optional audit target such as HIPAA, NIS2, FDA_524B, MDR_IVDR, ISO27001_ISO27799, HITRUST, AI_ACT, DCB0129_DCB0160, or THREAT_RESPONSE.',
          },
          baseline_control_ids: {
            type: 'array',
            items: { type: 'string' },
            description: 'Optional control IDs from build_healthcare_baseline.',
          },
          threat_ids: {
            type: 'array',
            items: { type: 'string' },
            description:
              'Optional threat IDs from get_healthcare_threats to generate threat-specific evidence annexes and artifact bundles.',
          },
          include_threat_appendix: {
            type: 'boolean',
            description:
              'Optional toggle to include or suppress threat_evidence_appendix output when threat_ids are provided.',
          },
          baseline: {
            type: 'object',
            description: 'Spec-compatible baseline object containing controls/prioritized_controls.',
          },
        },
      },
      handler: (db, args) => buildEvidencePlan(db, args),
    },
    {
      name: 'create_remediation_backlog',
      description:
        'Create prioritized remediation backlog from current control state and target baseline, including effort estimates and risk reduction notes.',
      inputSchema: {
        type: 'object',
        properties: {
          current_state: {
            type: 'object',
            description: 'Known implementation state used for delta-based prioritization.',
            properties: {
              implemented_controls: {
                type: 'array',
                items: { type: 'string' },
                description: 'Control IDs currently implemented.',
              },
              known_gaps: {
                type: 'array',
                items: { type: 'string' },
                description: 'Known deficiencies or missing control statements.',
              },
            },
          },
          target_baseline: {
            type: 'object',
            description: 'Baseline object from build_healthcare_baseline or compatible source.',
            properties: {
              controls: {
                type: 'array',
                items: { type: 'object' },
                description: 'Full control set to achieve.',
              },
              prioritized_controls: {
                type: 'array',
                items: { type: 'object' },
                description: 'Priority-ranked subset from the baseline output.',
              },
            },
          },
        },
        required: ['target_baseline'],
      },
      handler: (_db, args) => createRemediationBacklog(args),
    },
    {
      name: 'compare_jurisdictions',
      description:
        'Provide side-by-side healthcare obligation comparison cues across jurisdictions for a given topic, with explicit routes to the authoritative regulation/law MCPs to resolve final legal text.',
      inputSchema: {
        type: 'object',
        properties: {
          topic: {
            type: 'string',
            minLength: 3,
            description: 'Comparison topic such as breach notification, device cybersecurity, or cross-border transfers.',
          },
          jurisdictions: {
            type: 'array',
            items: { type: 'string' },
            minItems: 1,
            description: 'Jurisdictions to compare, usually US and EU.',
          },
          resolve_authoritative: {
            type: 'boolean',
            description: 'If true, also query configured upstream MCP endpoints and include live authoritative context.',
          },
          max_upstreams: {
            type: 'number',
            minimum: 1,
            maximum: 10,
            description: 'Optional cap for upstream MCP queries when resolve_authoritative=true.',
          },
        },
        required: ['topic', 'jurisdictions'],
      },
      handler: async (db, args) => compareJurisdictions(db, args),
    },
    {
      name: 'resolve_authoritative_context',
      description:
        'Resolve topic-specific authoritative context by querying configured upstream MCP endpoints (EU/US regulations, controls, law MCPs). Returns live upstream results, endpoint readiness, and tool selection status.',
      inputSchema: {
        type: 'object',
        properties: {
          topic: {
            type: 'string',
            minLength: 3,
            description: 'Healthcare compliance or threat-modeling topic to resolve against authoritative MCP sources.',
          },
          route_refs: {
            type: 'array',
            items: { type: 'string' },
            description: 'Optional explicit route references such as EU_Regulations_MCP or Security_Controls_MCP.',
          },
          jurisdictions: {
            type: 'array',
            items: { type: 'string' },
            description: 'Optional jurisdiction hints (US, EU).',
          },
          max_upstreams: {
            type: 'number',
            minimum: 1,
            maximum: 10,
            description: 'Limit the number of upstream MCP servers queried. Default: derived from routes and jurisdictions.',
          },
          max_tool_attempts: {
            type: 'number',
            minimum: 1,
            maximum: 5,
            description: 'Max argument-shape retries when invoking selected upstream tool. Default: 3.',
          },
        },
        required: ['topic'],
      },
      handler: async (db, args) => resolveAuthoritativeContext(db, args),
    },
    {
      name: 'get_protocol_security',
      description:
        'Return protocol-specific security profile for healthcare integration and exchange standards (HL7v2/FHIR/SMART/UDAP/CDA/openEHR, DICOM/DICOMweb, IHE/IEEE 11073 including XDS/MHD/XCA/XCPD/PIXm/PDQm/PCD, X12, NCPDP, SBOM/vulnerability exchange).',
      inputSchema: {
        type: 'object',
        properties: {
          protocol: {
            type: 'string',
            description: 'Protocol name.',
          },
        },
        required: ['protocol'],
      },
      handler: (_db, args) => getProtocolSecurity(args),
    },
    {
      name: 'assess_clinical_risk',
      description:
        'Assess patient safety impact for a threat scenario with ISO 14971-aligned severity/probability and risk acceptability guidance.',
      inputSchema: {
        type: 'object',
        properties: {
          threat_scenario: {
            type: 'string',
            minLength: 8,
            description: 'Threat narrative that could affect patient safety outcomes.',
          },
          device_context: {
            type: 'string',
            description: 'Optional device/product context when risk pertains to MedTech or IoMT.',
          },
          clinical_setting: {
            type: 'string',
            description: 'Optional care context such as ICU, OR, outpatient, or telehealth.',
          },
        },
        required: ['threat_scenario'],
      },
      handler: (_db, args) => assessClinicalRisk(args),
    },
    {
      name: 'map_hipaa_safeguards',
      description:
        'Map healthcare system context to HIPAA Security Rule administrative, physical, and technical safeguard expectations.',
      inputSchema: {
        type: 'object',
        properties: {
          system_description: {
            type: 'string',
            minLength: 8,
            description: 'Description of the healthcare system and workflow handling ePHI.',
          },
          data_types: {
            type: 'array',
            items: { type: 'string' },
            description: 'Optional data categories for tailoring safeguard recommendations.',
          },
        },
        required: ['system_description'],
      },
      handler: (_db, args) => mapHipaaSafeguards(args),
    },
  ];
}

export function registerTools(
  server: Server,
  db: SqlDatabase,
  context: AboutContext,
): void {
  const tools = createToolDefinitions(context);

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: tools.map((tool) => ({
      name: tool.name,
      description: tool.description,
      inputSchema: schemaWithExamples(tool.name, tool.inputSchema),
    })),
  }));

  server.setRequestHandler(
    CallToolRequestSchema,
    async (request: CallToolRequest): Promise<CallToolResult> => {
      const tool = tools.find((item) => item.name === request.params.name);

      if (!tool) {
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({ error: `Unknown tool: ${request.params.name}` }, null, 2),
            },
          ],
          isError: true,
        };
      }

      try {
        const result = await tool.handler(db, request.params.arguments ?? {});
        const wrapped = wrapWithMetadata(db, context, tool.name, result);
        const isToolError =
          result &&
          typeof result === 'object' &&
          'error' in (result as Record<string, unknown>) &&
          typeof (result as Record<string, unknown>).error === 'string';

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(wrapped, null, 2),
            },
          ],
          ...(isToolError ? { isError: true } : {}),
        };
      } catch (error) {
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  error: `Failed to execute ${tool.name}`,
                  details: error instanceof Error ? error.message : String(error),
                },
                null,
                2,
              ),
            },
          ],
          isError: true,
        };
      }
    },
  );
}
