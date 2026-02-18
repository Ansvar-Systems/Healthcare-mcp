#!/usr/bin/env tsx

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { openDatabase } from '../src/db.js';
import { buildDriftPayload } from './lib/drift-payload.js';

type StoredPayload = {
  hashes: Array<{ id: string; hash: string }>;
};

function main(): void {
  const db = openDatabase(true);
  const current = buildDriftPayload(db, '0.1.0');

  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);
  const fixturePath = join(__dirname, '..', 'fixtures', 'golden-hashes.json');
  const stored = JSON.parse(readFileSync(fixturePath, 'utf-8')) as StoredPayload;

  const storedMap = new Map(stored.hashes.map((entry) => [entry.id, entry.hash]));
  const failures: string[] = [];

  for (const entry of current.hashes) {
    const expected = storedMap.get(entry.id);
    if (!expected) {
      failures.push(`Missing hash entry in fixture: ${entry.id}`);
      continue;
    }
    if (expected !== entry.hash) {
      failures.push(`Hash mismatch for ${entry.id}: expected ${expected}, got ${entry.hash}`);
    }
  }

  const currentIds = new Set(current.hashes.map((entry) => entry.id));
  for (const entry of stored.hashes) {
    if (!currentIds.has(entry.id)) {
      failures.push(`Stale hash entry in fixture not generated anymore: ${entry.id}`);
    }
  }

  if (failures.length > 0) {
    console.error('❌ Drift hash verification failed:');
    for (const failure of failures) {
      console.error(`- ${failure}`);
    }
    console.error('\nRun npm run drift:hashes to regenerate fixtures/golden-hashes.json.');
    process.exit(1);
  }

  console.log('✅ Drift hashes match fixtures/golden-hashes.json');
}

main();
