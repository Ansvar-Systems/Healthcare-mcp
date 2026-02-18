import { describe, expect, it } from 'vitest';
import { openDatabase } from '../src/db.js';
import { assessBreachObligations } from '../src/tools/assess_breach_obligations.js';

describe('breach routing depth coverage', () => {
  const db = openDatabase(true);

  it('uses exact NL jurisdiction breach routing for member-state healthcare data', () => {
    const output = assessBreachObligations(db, {
      jurisdictions: ['NL'],
      data_categories: ['health_data'],
      incident_summary: 'Unauthorized access to hospital records in Dutch care network',
    }) as {
      notifications: Array<{
        requested_jurisdiction: string;
        rule_jurisdiction: string;
        source_router: string;
      }>;
    };

    const nlExact = output.notifications.find(
      (item) => item.requested_jurisdiction === 'NL' && item.rule_jurisdiction === 'NL',
    );
    expect(nlExact).toBeDefined();
    expect((nlExact?.source_router ?? '').toLowerCase()).toContain('nl-law-mcp');
  });

  it('combines exact US-FL state breach routing with US family fallback', () => {
    const output = assessBreachObligations(db, {
      jurisdictions: ['US-FL'],
      data_categories: ['ephi'],
      incident_summary: 'Large healthcare data breach involving patient files',
    }) as {
      strictest_deadline: { deadline_hours: number } | null;
      notifications: Array<{
        requested_jurisdiction: string;
        rule_jurisdiction: string;
      }>;
    };

    const hasState = output.notifications.some(
      (item) => item.requested_jurisdiction === 'US-FL' && item.rule_jurisdiction === 'US-FL',
    );
    const hasFamily = output.notifications.some(
      (item) => item.requested_jurisdiction === 'US-FL' && item.rule_jurisdiction === 'US',
    );

    expect(hasState).toBe(true);
    expect(hasFamily).toBe(true);
    expect(output.strictest_deadline?.deadline_hours).toBe(720);
  });

  it('handles mixed FR and US-IL jurisdictions with distinct notification matrix entries', () => {
    const output = assessBreachObligations(db, {
      jurisdictions: ['FR', 'US-IL'],
      data_categories: ['health_data', 'ehds_secondary_use'],
      incident_summary: 'Cross-border healthcare dataset breach affecting EU and US operations',
    }) as {
      notification_matrix: Array<{ jurisdiction: string; notifications: Array<unknown> }>;
      strictest_deadline: { deadline_hours: number } | null;
    };

    const fr = output.notification_matrix.find((item) => item.jurisdiction === 'FR');
    const usIl = output.notification_matrix.find((item) => item.jurisdiction === 'US-IL');

    expect(fr).toBeDefined();
    expect(usIl).toBeDefined();
    expect((fr?.notifications ?? []).length).toBeGreaterThan(0);
    expect((usIl?.notifications ?? []).length).toBeGreaterThan(0);
    expect((output.strictest_deadline?.deadline_hours ?? 9999)).toBeLessThanOrEqual(72);
  });
});
