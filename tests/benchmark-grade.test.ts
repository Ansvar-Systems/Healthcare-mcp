import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { openDatabase } from '../src/db.js';
import { assessBreachObligations } from '../src/tools/assess_breach_obligations.js';
import { assessClinicalRisk } from '../src/tools/assess_clinical_risk.js';
import { assessHealthcareApplicability } from '../src/tools/assess_healthcare_applicability.js';
import { buildEvidencePlan } from '../src/tools/build_evidence_plan.js';
import { classifyHealthData } from '../src/tools/classify_health_data.js';
import { compareJurisdictions } from '../src/tools/compare_jurisdictions.js';
import { getArchitecturePattern } from '../src/tools/get_architecture_pattern.js';
import { getHealthcareThreats } from '../src/tools/get_healthcare_threats.js';
import { getProtocolSecurity } from '../src/tools/get_protocol_security.js';
import { getThreatResponsePlaybook } from '../src/tools/get_threat_response_playbook.js';
import { mapToHealthcareStandards } from '../src/tools/map_to_healthcare_standards.js';
import { resolveAuthoritativeContext } from '../src/tools/resolve_authoritative_context.js';
import { searchDomainKnowledge } from '../src/tools/search_domain_knowledge.js';

type Operator = 'equals' | 'min_count' | 'contains' | 'max_number' | 'has_key';

type ScenarioAssertion = {
  path: string;
  operator: Operator;
  expected: unknown;
};

type BenchmarkScenario = {
  id: string;
  weight: number;
  tool: string;
  input: Record<string, unknown>;
  assertions: ScenarioAssertion[];
};

type BenchmarkFixture = {
  version: string;
  minimum_score: number;
  scenarios: BenchmarkScenario[];
};

function getPathValue(value: unknown, path: string): unknown {
  return path.split('.').reduce<unknown>((current, key) => {
    if (current && typeof current === 'object') {
      return (current as Record<string, unknown>)[key];
    }
    return undefined;
  }, value);
}

function evaluateAssertion(payload: unknown, assertion: ScenarioAssertion): boolean {
  const actual = getPathValue(payload, assertion.path);

  switch (assertion.operator) {
    case 'equals':
      return actual === assertion.expected;
    case 'min_count':
      return Array.isArray(actual) && actual.length >= Number(assertion.expected);
    case 'contains':
      if (Array.isArray(actual)) {
        return actual.includes(assertion.expected);
      }
      if (typeof actual === 'string') {
        return actual.includes(String(assertion.expected));
      }
      return false;
    case 'max_number':
      return typeof actual === 'number' && actual <= Number(assertion.expected);
    case 'has_key':
      return Boolean(
        actual &&
          typeof actual === 'object' &&
          Object.prototype.hasOwnProperty.call(actual, String(assertion.expected)),
      );
    default:
      return false;
  }
}

describe('expert benchmark grade gate', () => {
  const db = openDatabase(true);
  const fixturePath = join(process.cwd(), 'fixtures', 'expert-benchmark.json');
  const fixture = JSON.parse(readFileSync(fixturePath, 'utf-8')) as BenchmarkFixture;
  const minimumScore = Number(process.env.BENCHMARK_MIN_SCORE ?? fixture.minimum_score);

  async function runTool(tool: string, input: Record<string, unknown>): Promise<unknown> {
    switch (tool) {
      case 'classify_health_data':
        return classifyHealthData(db, input);
      case 'get_architecture_pattern':
        return getArchitecturePattern(db, input);
      case 'get_healthcare_threats':
        return getHealthcareThreats(db, input);
      case 'assess_applicability':
        return assessHealthcareApplicability(db, input);
      case 'compare_jurisdictions':
        return compareJurisdictions(db, input);
      case 'map_to_healthcare_standards':
        return mapToHealthcareStandards(db, input);
      case 'assess_breach_obligations':
        return assessBreachObligations(db, input);
      case 'search_domain_knowledge':
        return searchDomainKnowledge(db, input);
      case 'assess_clinical_risk':
        return assessClinicalRisk(input);
      case 'build_evidence_plan':
        return buildEvidencePlan(db, input);
      case 'get_protocol_security':
        return getProtocolSecurity(input);
      case 'resolve_authoritative_context':
        return resolveAuthoritativeContext(db, input);
      case 'get_threat_response_playbook':
        return getThreatResponsePlaybook(db, input);
      default:
        throw new Error(`Unsupported benchmark tool: ${tool}`);
    }
  }

  it(`meets benchmark minimum score of ${minimumScore}`, async () => {
    let score = 0;
    let totalWeight = 0;
    const failed: string[] = [];

    for (const scenario of fixture.scenarios) {
      totalWeight += scenario.weight;
      const output = await runTool(scenario.tool, scenario.input);
      const pass = scenario.assertions.every((assertion) => evaluateAssertion(output, assertion));
      if (pass) {
        score += scenario.weight;
      } else {
        failed.push(scenario.id);
      }
    }

    if (failed.length > 0) {
      // Surface failing benchmark IDs in the test output for fast triage.
      // eslint-disable-next-line no-console
      console.error(`Benchmark failures: ${failed.join(', ')}`);
    }

    expect(totalWeight).toBeGreaterThan(0);
    expect(score).toBeGreaterThanOrEqual(minimumScore);
  });
});
