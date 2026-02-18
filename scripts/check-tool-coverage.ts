#!/usr/bin/env tsx

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { computeAboutContext } from '../src/db.js';
import { createToolDefinitions } from '../src/tools/registry.js';

const ROOT = process.cwd();
const TEST_ROOT = join(ROOT, 'tests');
const FIXTURE_FILES = [join(ROOT, 'fixtures', 'golden-tests.json'), join(ROOT, 'fixtures', 'expert-benchmark.json')];
const ALIAS_TOOLS = new Set([
  'classify_data',
  'get_domain_threats',
  'assess_applicability',
  'map_to_technical_standards',
  'build_control_baseline',
]);

function collectFiles(dir: string): string[] {
  const entries = readdirSync(dir, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const absolutePath = join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...collectFiles(absolutePath));
      continue;
    }
    if (entry.isFile() && absolutePath.endsWith('.ts')) {
      files.push(absolutePath);
    }
  }
  return files;
}

function containsToken(haystack: string, token: string): boolean {
  const escaped = token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const pattern = new RegExp(`(^|[^a-zA-Z0-9_-])${escaped}([^a-zA-Z0-9_-]|$)`);
  return pattern.test(haystack);
}

function main(): void {
  const tools = createToolDefinitions(computeAboutContext('0.1.0'))
    .map((tool) => tool.name)
    .filter((name) => !ALIAS_TOOLS.has(name));

  const testFiles = collectFiles(TEST_ROOT);
  const corpusParts = testFiles.map((file) => readFileSync(file, 'utf-8'));
  for (const fixtureFile of FIXTURE_FILES) {
    corpusParts.push(readFileSync(fixtureFile, 'utf-8'));
  }
  const corpus = corpusParts.join('\n');

  const missing = tools.filter((toolName) => !containsToken(corpus, toolName));
  if (missing.length > 0) {
    console.error('❌ Tool coverage gate failed. Tools missing explicit test/fixture references:');
    for (const tool of missing) {
      console.error(`- ${tool}`);
    }
    process.exit(1);
  }

  console.log(`✅ Tool coverage gate passed (${tools.length} canonical tools referenced).`);
}

main();
