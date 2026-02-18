import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { openDatabase } from '../src/db.js';
import { resolveAuthoritativeContext } from '../src/tools/resolve_authoritative_context.js';
import { compareJurisdictions } from '../src/tools/compare_jurisdictions.js';

function jsonRpcResult(id: number, result: unknown, sessionId?: string): Response {
  const headers = new Headers({ 'content-type': 'application/json' });
  if (sessionId) {
    headers.set('mcp-session-id', sessionId);
  }
  return new Response(
    JSON.stringify({
      jsonrpc: '2.0',
      id,
      result,
    }),
    { status: 200, headers },
  );
}

describe('resolve_authoritative_context', () => {
  const db = openDatabase(true);

  beforeEach(() => {
    process.env.HEALTHCARE_UPSTREAM_EU_REGS_URL = 'https://eu.example/mcp';
    process.env.HEALTHCARE_UPSTREAM_SECURITY_CONTROLS_URL = 'https://controls.example/mcp';
    delete process.env.HEALTHCARE_UPSTREAM_EU_LAW_URL;

    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const body = JSON.parse(String(init?.body ?? '{}')) as {
        id: number;
        method: string;
        params?: { name?: string };
      };

      if (url.includes('eu.example')) {
        if (body.method === 'initialize') {
          return jsonRpcResult(body.id, { protocolVersion: '2025-03-26' }, 'eu-session');
        }
        if (body.method === 'tools/list') {
          return jsonRpcResult(
            body.id,
            { tools: [{ name: 'search_requirements', description: 'Search requirements' }] },
            'eu-session',
          );
        }
        if (body.method === 'tools/call' && body.params?.name === 'search_requirements') {
          return jsonRpcResult(
            body.id,
            {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify({
                    citations: ['GDPR_ART_9'],
                    results: [{ reference: 'GDPR_ART_9', summary: 'Special category health data constraints' }],
                  }),
                },
              ],
            },
            'eu-session',
          );
        }
      }

      if (url.includes('controls.example')) {
        if (body.method === 'initialize') {
          return jsonRpcResult(body.id, { protocolVersion: '2025-03-26' }, 'controls-session');
        }
        if (body.method === 'tools/list') {
          return jsonRpcResult(
            body.id,
            { tools: [{ name: 'search_controls', description: 'Search control framework items' }] },
            'controls-session',
          );
        }
        if (body.method === 'tools/call' && body.params?.name === 'search_controls') {
          return jsonRpcResult(
            body.id,
            {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify({
                    controls: [{ id: 'AC-6', framework: 'NIST_800_53' }],
                  }),
                },
              ],
            },
            'controls-session',
          );
        }
      }

      return new Response(
        JSON.stringify({
          jsonrpc: '2.0',
          id: body.id,
          error: { code: -32601, message: 'Method not found' },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    });

    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    delete process.env.HEALTHCARE_UPSTREAM_EU_REGS_URL;
    delete process.env.HEALTHCARE_UPSTREAM_SECURITY_CONTROLS_URL;
  });

  it('queries configured upstream MCP servers and returns mixed readiness summary', async () => {
    const result = (await resolveAuthoritativeContext(db, {
      topic: 'GDPR obligations and control baseline for hospital APIs',
      jurisdictions: ['EU'],
      max_upstreams: 5,
    })) as {
      summary: { ok: number; not_configured: number };
      upstream_results: Array<{ status: string; kind: string; data?: unknown }>;
    };

    expect(result.summary.ok).toBe(2);
    expect(result.summary.not_configured).toBeGreaterThanOrEqual(1);

    const euRegs = result.upstream_results.find((item) => item.kind === 'EU_REGULATIONS');
    expect(euRegs?.status).toBe('ok');

    const controls = result.upstream_results.find((item) => item.kind === 'SECURITY_CONTROLS');
    expect(controls?.status).toBe('ok');
  });

  it('embeds authoritative context when compare_jurisdictions resolve_authoritative is enabled', async () => {
    const result = (await compareJurisdictions(db, {
      topic: 'breach notification',
      jurisdictions: ['EU'],
      resolve_authoritative: true,
    })) as {
      comparison: Array<unknown>;
      authoritative_context?: { summary?: { ok?: number } };
    };

    expect(result.comparison.length).toBeGreaterThan(0);
    expect(result.authoritative_context?.summary?.ok).toBeGreaterThanOrEqual(1);
  });
});
