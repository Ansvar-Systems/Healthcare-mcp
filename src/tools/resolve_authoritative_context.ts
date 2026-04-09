import type { SqlDatabase } from '../db.js';
import type { ResolveAuthoritativeContextInput, ToolError } from '../types.js';
import {
  mapRouteRefsToKinds,
  jurisdictionsToKinds,
  queryUpstream,
  type UpstreamKind,
} from '../integrations/upstream_router.js';
import { responseMeta } from './response-meta.js';

function deriveRouteRefs(
  db: SqlDatabase,
  topic: string,
  routeRefs?: string[],
): string[] {
  if (routeRefs && routeRefs.length > 0) {
    return routeRefs;
  }

  const lowered = topic.toLowerCase();
  const refs: string[] = [];

  if (lowered.includes('hipaa') || lowered.includes('hitech') || lowered.includes('fda')) {
    refs.push('US_Regulations_MCP');
  }
  if (lowered.includes('gdpr') || lowered.includes('nis2') || lowered.includes('ehds') || lowered.includes('mdr')) {
    refs.push('EU_Regulations_MCP');
  }
  if (lowered.includes('control') || lowered.includes('baseline') || lowered.includes('framework')) {
    refs.push('Security_Controls_MCP');
  }
  if (lowered.includes('state law')) {
    refs.push('US-law-mcp');
  }

  if (refs.length === 0) {
    const defaultRefs = db
      .prepare('SELECT DISTINCT source_router FROM obligation_profiles ORDER BY source_router')
      .all() as Array<{ source_router: string }>;
    refs.push(...defaultRefs.map((row) => row.source_router));
  }

  return [...new Set(refs)];
}

export async function resolveAuthoritativeContext(
  db: SqlDatabase,
  args: unknown,
): Promise<Record<string, unknown> | ToolError> {
  const input = args as ResolveAuthoritativeContextInput;

  if (!input?.topic || input.topic.trim().length < 3) {
    return {
      error: 'topic is required and must be at least 3 characters',
      hint: 'Example: "HIPAA and GDPR obligations for SMART on FHIR token breach"',
    };
  }

  const routes = deriveRouteRefs(db, input.topic, input.route_refs);

  const routeKinds = mapRouteRefsToKinds(routes);
  const jurisdictionKinds = input.jurisdictions
    ? jurisdictionsToKinds(input.jurisdictions)
    : [];

  const combinedKinds = [...new Set<UpstreamKind>([...routeKinds, ...jurisdictionKinds])];
  const defaultUpstreamCount = combinedKinds.length > 0 ? combinedKinds.length : 5;
  const maxUpstreams = Math.max(1, Math.min(10, input.max_upstreams ?? defaultUpstreamCount));
  const selectedKinds = combinedKinds.slice(0, maxUpstreams);

  const results = await Promise.all(
    selectedKinds.map((kind) =>
      queryUpstream(kind, {
        topic: input.topic,
        jurisdictions: input.jurisdictions ?? [],
        maxToolAttempts: input.max_tool_attempts ?? 3,
      }),
    ),
  );

  const summary = {
    ok: results.filter((item) => item.status === 'ok').length,
    not_configured: results.filter((item) => item.status === 'not_configured').length,
    tool_not_found: results.filter((item) => item.status === 'tool_not_found').length,
    errors: results.filter((item) => item.status === 'error').length,
  };

  return {
    topic: input.topic,
    routes,
    jurisdictions: input.jurisdictions ?? [],
    selected_upstreams: selectedKinds,
    summary,
    upstream_results: results,
    guidance: [
      'Treat upstream result payloads as authoritative only if citations and effective dates are present.',
      'Fallback to route-only mode when endpoint configuration is missing.',
    ],
    ...responseMeta(),
  };
}
