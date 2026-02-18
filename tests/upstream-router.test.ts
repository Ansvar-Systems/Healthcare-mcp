import { describe, expect, it } from 'vitest';
import { jurisdictionsToKinds, mapRouteRefsToKinds } from '../src/integrations/upstream_router.js';

describe('upstream router helpers', () => {
  it('maps route refs to expected upstream kinds', () => {
    const kinds = mapRouteRefsToKinds([
      'EU_Regulations_MCP',
      'Security_Controls_MCP',
      'US-law-mcp',
    ]);

    expect(kinds).toContain('EU_REGULATIONS');
    expect(kinds).toContain('SECURITY_CONTROLS');
    expect(kinds).toContain('US_LAW');
  });

  it('maps jurisdictions to core upstream kinds', () => {
    const kinds = jurisdictionsToKinds(['US', 'EU']);

    expect(kinds).toContain('EU_REGULATIONS');
    expect(kinds).toContain('US_REGULATIONS');
    expect(kinds).toContain('SECURITY_CONTROLS');
  });

  it('maps country-coded jurisdictions to the correct upstream families', () => {
    const kinds = jurisdictionsToKinds(['US-CA', 'SE']);

    expect(kinds).toContain('US_REGULATIONS');
    expect(kinds).toContain('US_LAW');
    expect(kinds).toContain('EU_REGULATIONS');
    expect(kinds).toContain('EU_LAW');
    expect(kinds).toContain('SECURITY_CONTROLS');
  });
});
