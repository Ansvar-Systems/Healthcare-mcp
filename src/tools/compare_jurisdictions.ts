import type Database from 'better-sqlite3';
import { jurisdictionFamily, normalizeJurisdictionCode } from '../jurisdictions.js';
import type { CompareJurisdictionsInput, ToolError } from '../types.js';
import { resolveAuthoritativeContext } from './resolve_authoritative_context.js';

function containsAny(value: string, terms: string[]): boolean {
  const normalized = value.toLowerCase();
  return terms.some((term) => normalized.includes(term));
}

export async function compareJurisdictions(
  db: Database.Database,
  args: unknown,
): Promise<Record<string, unknown> | ToolError> {
  const input = args as CompareJurisdictionsInput;

  if (!input?.topic || !input?.jurisdictions?.length) {
    return {
      error: 'topic and jurisdictions are required',
      hint: 'Example: {"topic":"breach notification for ePHI", "jurisdictions":["US","EU"]}',
    };
  }

  const topic = input.topic.toLowerCase();
  const jurisdictions = [...new Set(input.jurisdictions.map((item) => normalizeJurisdictionCode(item)))];
  const jurisdictionContext = jurisdictions.map((jurisdiction) => {
    const family = jurisdictionFamily(jurisdiction);
    const ruleJurisdiction = family === 'US' ? 'US' : family === 'EU' ? 'EU' : jurisdiction;
    return {
      requested: jurisdiction,
      family,
      rule_jurisdiction: ruleJurisdiction,
    };
  });

  const comparisonRows: Array<Record<string, unknown>> = [];

  if (containsAny(topic, ['breach', 'incident', 'notification'])) {
    const exactRuleLookup = db.prepare(
      `SELECT jurisdiction, trigger_category, deadline_hours, notify_parties, source_router
       FROM breach_rules
       WHERE jurisdiction = ?
       ORDER BY deadline_hours ASC`,
    );

    for (const entry of jurisdictionContext) {
      const candidates = [entry.requested, entry.rule_jurisdiction];
      const candidateRules = candidates
        .flatMap((candidate) =>
          exactRuleLookup.all(candidate) as Array<{
            jurisdiction: string;
            trigger_category: string;
            deadline_hours: number;
            notify_parties: string;
            source_router: string;
          }>,
        )
        .sort((a, b) => a.deadline_hours - b.deadline_hours);
      const rule = candidateRules[0];

      if (!rule) {
        comparisonRows.push({
          jurisdiction: entry.requested,
          topic: 'breach_notification',
          authoritative_route:
            entry.family === 'US'
              ? 'US_Regulations_MCP:HIPAA_BREACH + US-law-mcp:state_breach'
              : entry.family === 'EU'
                ? 'EU_Regulations_MCP:GDPR_ART_33 + EU-law-mcp:member_state_breach'
                : 'law MCP router',
          note: 'No direct breach-rule profile found in current dataset.',
          confidence: 'estimated',
        });
        continue;
      }

      comparisonRows.push({
        jurisdiction: entry.requested,
        rule_jurisdiction: rule.jurisdiction,
        topic: 'breach_notification',
        trigger_category: rule.trigger_category,
        deadline_hours: rule.deadline_hours,
        notify_parties: JSON.parse(rule.notify_parties),
        authoritative_route: rule.source_router,
        confidence: 'inferred',
      });
    }
  }

  if (containsAny(topic, ['device', 'samd', 'fda', 'mdr'])) {
    for (const entry of jurisdictionContext) {
      if (entry.family === 'US') {
        comparisonRows.push({
          jurisdiction: entry.requested,
          topic: 'medical_device_cybersecurity',
          authoritative_route: 'US_Regulations_MCP:FDA_524B',
          standards_route: 'map_to_healthcare_standards -> IEC_62304, ISO_14971',
          confidence: 'inferred',
        });
        continue;
      }

      if (entry.family === 'EU') {
        comparisonRows.push({
          jurisdiction: entry.requested,
          topic: 'medical_device_cybersecurity',
          authoritative_route: 'EU_Regulations_MCP:MDR_IVDR',
          standards_route: 'map_to_healthcare_standards -> IEC_62304, ISO_14971, IEC_80001_1',
          confidence: 'inferred',
        });
        continue;
      }

      comparisonRows.push({
        jurisdiction: entry.requested,
        topic: 'medical_device_cybersecurity',
        authoritative_route: 'Jurisdiction not mapped to US/EU device profile',
        confidence: 'estimated',
      });
    }
  }

  if (comparisonRows.length === 0) {
    comparisonRows.push(
      ...jurisdictionContext.map((entry) => ({
        jurisdiction: entry.requested,
        topic: input.topic,
        authoritative_route:
          entry.family === 'US'
            ? 'US_Regulations_MCP + US-law-mcp'
            : entry.family === 'EU'
              ? 'EU_Regulations_MCP + member-state law MCP'
              : 'law MCP router',
        note: 'No specialized comparator rule yet for this topic; use resolve_authoritative_context for live retrieval.',
        confidence: 'estimated',
      })),
    );
  }

  const strictestDeadline = comparisonRows
    .filter((item) => typeof item.deadline_hours === 'number')
    .sort((a, b) => Number(a.deadline_hours) - Number(b.deadline_hours))[0] ?? null;

  const output: Record<string, unknown> = {
    topic: input.topic,
    jurisdictions,
    comparison: comparisonRows,
    comparison_matrix: comparisonRows,
    strictest_deadline: strictestDeadline,
    synthesis_guidance: [
      'Use strictest timeline and highest protection threshold when obligations conflict.',
      'Validate local/state/member-state overlays before final recommendation.',
      'Call resolve_authoritative_context for live source retrieval from configured upstream MCP endpoints.',
    ],
  };

  if (input.resolve_authoritative) {
    output.authoritative_context = await resolveAuthoritativeContext(db, {
      topic: input.topic,
      jurisdictions,
      max_upstreams: input.max_upstreams,
    });
  }

  return output;
}
