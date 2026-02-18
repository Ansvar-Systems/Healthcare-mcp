import { describe, expect, it } from 'vitest';
import { openDatabase } from '../src/db.js';
import { resolveAuthoritativeContext } from '../src/tools/resolve_authoritative_context.js';

const RUN_LIVE = process.env.LIVE_UPSTREAM_TESTS === '1';
const describeLive = RUN_LIVE ? describe : describe.skip;
const STRICT = process.env.LIVE_STRICT === '1';
const MIN_OK_RATIO = Number(process.env.LIVE_REQUIRED_MIN_OK_RATIO ?? '0.8');

function configuredRouteRefs(): string[] {
  const refs: string[] = [];

  if (process.env.HEALTHCARE_UPSTREAM_EU_REGS_URL) {
    refs.push('EU_Regulations_MCP');
  }
  if (process.env.HEALTHCARE_UPSTREAM_US_REGS_URL) {
    refs.push('US_Regulations_MCP');
  }
  if (process.env.HEALTHCARE_UPSTREAM_SECURITY_CONTROLS_URL) {
    refs.push('Security_Controls_MCP');
  }
  if (process.env.HEALTHCARE_UPSTREAM_US_LAW_URL) {
    refs.push('US-law-mcp');
  }
  if (process.env.HEALTHCARE_UPSTREAM_EU_LAW_URL) {
    refs.push('member-state law MCP');
  }

  return refs;
}

describeLive('live authoritative upstream regression', () => {
  const db = openDatabase(true);

  it('queries all configured upstream MCPs without falling back to not_configured', async () => {
    const routeRefs = configuredRouteRefs();
    expect(routeRefs.length).toBeGreaterThan(0);

    const result = (await resolveAuthoritativeContext(db, {
      topic: 'healthcare breach notification and technical safeguards',
      route_refs: routeRefs,
      max_upstreams: routeRefs.length,
      max_tool_attempts: 3,
    })) as {
      summary: { ok: number; not_configured: number; errors: number };
      upstream_results: Array<{ status: string; endpoint: string | null; selected_tool?: string }>;
    };

    expect(result.summary.not_configured).toBe(0);
    expect(result.summary.errors).toBe(0);
    expect(result.summary.ok).toBeGreaterThan(0);

    for (const upstream of result.upstream_results) {
      expect(upstream.endpoint).not.toBeNull();
      expect(upstream.status).toBe('ok');
      expect(typeof upstream.selected_tool === 'string' || upstream.selected_tool === undefined).toBe(true);
    }
  });

  it('returns at least one parseable authoritative payload from upstream', async () => {
    const routeRefs = configuredRouteRefs();
    expect(routeRefs.length).toBeGreaterThan(0);

    const result = (await resolveAuthoritativeContext(db, {
      topic: 'GDPR Article 9 and HIPAA Security Rule',
      route_refs: routeRefs,
      max_upstreams: routeRefs.length,
    })) as {
      upstream_results: Array<{ status: string; data?: unknown }>;
    };

    const okPayloads = result.upstream_results
      .filter((item) => item.status === 'ok')
      .map((item) => item.data)
      .filter((item) => item !== undefined && item !== null);

    expect(okPayloads.length).toBeGreaterThan(0);
  });

  it('meets configured live upstream success threshold', async () => {
    const routeRefs = configuredRouteRefs();
    expect(routeRefs.length).toBeGreaterThan(0);

    const result = (await resolveAuthoritativeContext(db, {
      topic: 'healthcare device security and breach obligations',
      route_refs: routeRefs,
      max_upstreams: routeRefs.length,
      max_tool_attempts: 3,
    })) as {
      summary: { ok: number };
      upstream_results: Array<{ status: string; kind?: string; label?: string }>;
    };

    const configuredCount = routeRefs.length;
    const okCount = result.summary.ok;
    const okRatio = configuredCount > 0 ? okCount / configuredCount : 0;

    if (STRICT) {
      expect(okCount).toBe(configuredCount);
      return;
    }

    if (okRatio < MIN_OK_RATIO) {
      const failures = result.upstream_results
        .filter((item) => item.status !== 'ok')
        .map((item) => `${item.label ?? item.kind ?? 'unknown'}:${item.status}`);
      throw new Error(
        `Live upstream success ratio ${okRatio.toFixed(2)} below threshold ${MIN_OK_RATIO.toFixed(2)}. Failures: ${failures.join(', ')}`,
      );
    }

    expect(okRatio).toBeGreaterThanOrEqual(MIN_OK_RATIO);
  });
});
