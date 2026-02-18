import { McpHttpClient, type McpToolSummary } from './mcp_http_client.js';
import { isEuJurisdiction, isUsJurisdiction, normalizeJurisdictionCode } from '../jurisdictions.js';

export type UpstreamKind =
  | 'EU_REGULATIONS'
  | 'US_REGULATIONS'
  | 'SECURITY_CONTROLS'
  | 'US_LAW'
  | 'EU_LAW';

export interface UpstreamConfig {
  kind: UpstreamKind;
  label: string;
  endpoint: string;
}

interface QueryUpstreamArgs {
  topic: string;
  jurisdictions?: string[];
  maxToolAttempts?: number;
}

export interface UpstreamQueryResult {
  kind: UpstreamKind;
  label: string;
  endpoint: string | null;
  status: 'ok' | 'not_configured' | 'tool_not_found' | 'error';
  selected_tool?: string;
  tools_available?: string[];
  summary?: string;
  data?: unknown;
  error?: string;
}

const ENV_MAP: Record<UpstreamKind, string> = {
  EU_REGULATIONS: 'HEALTHCARE_UPSTREAM_EU_REGS_URL',
  US_REGULATIONS: 'HEALTHCARE_UPSTREAM_US_REGS_URL',
  SECURITY_CONTROLS: 'HEALTHCARE_UPSTREAM_SECURITY_CONTROLS_URL',
  US_LAW: 'HEALTHCARE_UPSTREAM_US_LAW_URL',
  EU_LAW: 'HEALTHCARE_UPSTREAM_EU_LAW_URL',
};

const LABEL_MAP: Record<UpstreamKind, string> = {
  EU_REGULATIONS: 'EU Regulations MCP',
  US_REGULATIONS: 'US Regulations MCP',
  SECURITY_CONTROLS: 'Security Controls MCP',
  US_LAW: 'US Law MCP',
  EU_LAW: 'EU Law MCP',
};

const TOOL_PRIORITY: Record<UpstreamKind, string[]> = {
  EU_REGULATIONS: ['search_requirements', 'search_regulations', 'search_legislation', 'search_articles'],
  US_REGULATIONS: ['search_requirements', 'search_regulations', 'search_legislation', 'search_sections'],
  SECURITY_CONTROLS: ['search_controls', 'search_requirements', 'get_control', 'map_controls'],
  US_LAW: ['search_legislation', 'search_law', 'search_provisions'],
  EU_LAW: ['search_legislation', 'search_law', 'search_provisions'],
};

const TOOL_ARG_CANDIDATES: Array<Record<string, unknown>> = [
  { query: '', limit: 5 },
  { query: '', max_results: 5 },
  { text: '', limit: 5 },
  { term: '', limit: 5 },
];

export function getConfiguredUpstream(kind: UpstreamKind): UpstreamConfig | null {
  const envKey = ENV_MAP[kind];
  const endpoint = process.env[envKey];
  if (!endpoint) {
    return null;
  }

  return {
    kind,
    label: LABEL_MAP[kind],
    endpoint,
  };
}

export function mapRouteRefsToKinds(routeRefs: string[]): UpstreamKind[] {
  const kinds = new Set<UpstreamKind>();

  for (const route of routeRefs) {
    const normalized = route.toLowerCase();

    if (normalized.includes('eu_regulations_mcp') || normalized.includes('gdpr') || normalized.includes('nis2')) {
      kinds.add('EU_REGULATIONS');
    }
    if (normalized.includes('us_regulations_mcp') || normalized.includes('hipaa') || normalized.includes('hitech')) {
      kinds.add('US_REGULATIONS');
    }
    if (normalized.includes('security_controls_mcp') || normalized.includes('control')) {
      kinds.add('SECURITY_CONTROLS');
    }
    if (normalized.includes('us-law-mcp') || normalized.includes('state')) {
      kinds.add('US_LAW');
    }
    if (normalized.includes('member-state') || normalized.includes('eu law') || normalized.includes('law mcp')) {
      kinds.add('EU_LAW');
    }
  }

  return [...kinds];
}

export function jurisdictionsToKinds(jurisdictions: string[]): UpstreamKind[] {
  const normalized = jurisdictions.map((item) => normalizeJurisdictionCode(item));
  const kinds = new Set<UpstreamKind>();

  for (const code of normalized) {
    if (code === 'US_EU') {
      kinds.add('EU_REGULATIONS');
      kinds.add('EU_LAW');
      kinds.add('US_REGULATIONS');
      kinds.add('US_LAW');
      continue;
    }

    if (isEuJurisdiction(code)) {
      kinds.add('EU_REGULATIONS');
      kinds.add('EU_LAW');
    }

    if (isUsJurisdiction(code)) {
      kinds.add('US_REGULATIONS');
      kinds.add('US_LAW');
    }
  }

  kinds.add('SECURITY_CONTROLS');

  return [...kinds];
}

function pickTool(tools: McpToolSummary[], kind: UpstreamKind): string | null {
  const names = new Set(tools.map((tool) => tool.name));
  for (const preferred of TOOL_PRIORITY[kind]) {
    if (names.has(preferred)) {
      return preferred;
    }
  }
  if (names.has('about')) {
    return 'about';
  }
  return null;
}

async function callBestEffort(
  client: McpHttpClient,
  toolName: string,
  topic: string,
  jurisdictions: string[],
  maxToolAttempts: number,
): Promise<{ ok: boolean; parsed?: unknown; text?: string; error?: string }> {
  if (toolName === 'about') {
    try {
      const about = await client.callTool('about', {});
      return { ok: true, parsed: about.parsed, text: about.text };
    } catch (error) {
      return { ok: false, error: error instanceof Error ? error.message : String(error) };
    }
  }

  const attempts = TOOL_ARG_CANDIDATES.slice(0, Math.max(1, maxToolAttempts));

  for (const template of attempts) {
    const args = {
      ...template,
      query: typeof template.query === 'string' ? topic : template.query,
      text: typeof template.text === 'string' ? topic : template.text,
      term: typeof template.term === 'string' ? topic : template.term,
      jurisdictions,
    };

    try {
      const result = await client.callTool(toolName, args);
      return { ok: true, parsed: result.parsed, text: result.text };
    } catch {
      // Try next candidate argument shape.
    }
  }

  return { ok: false, error: `Unable to call ${toolName} with known argument patterns.` };
}

export async function queryUpstream(
  kind: UpstreamKind,
  args: QueryUpstreamArgs,
): Promise<UpstreamQueryResult> {
  const config = getConfiguredUpstream(kind);
  if (!config) {
    return {
      kind,
      label: LABEL_MAP[kind],
      endpoint: null,
      status: 'not_configured',
      summary: `Set ${ENV_MAP[kind]} to enable live routing for ${LABEL_MAP[kind]}.`,
    };
  }

  try {
    const client = new McpHttpClient({ endpoint: config.endpoint });
    await client.initialize();
    const tools = await client.listTools();
    const selectedTool = pickTool(tools, kind);

    if (!selectedTool) {
      return {
        kind,
        label: config.label,
        endpoint: config.endpoint,
        status: 'tool_not_found',
        tools_available: tools.map((tool) => tool.name),
        summary: 'No compatible search or about tool found on upstream server.',
      };
    }

    const callResult = await callBestEffort(
      client,
      selectedTool,
      args.topic,
      args.jurisdictions ?? [],
      args.maxToolAttempts ?? 3,
    );

    if (!callResult.ok) {
      return {
        kind,
        label: config.label,
        endpoint: config.endpoint,
        status: 'error',
        selected_tool: selectedTool,
        tools_available: tools.map((tool) => tool.name),
        error: callResult.error,
      };
    }

    return {
      kind,
      label: config.label,
      endpoint: config.endpoint,
      status: 'ok',
      selected_tool: selectedTool,
      tools_available: tools.map((tool) => tool.name),
      summary: 'Authoritative context retrieved from upstream MCP.',
      data: callResult.parsed,
    };
  } catch (error) {
    return {
      kind,
      label: config.label,
      endpoint: config.endpoint,
      status: 'error',
      error: error instanceof Error ? error.message : String(error),
    };
  }
}
