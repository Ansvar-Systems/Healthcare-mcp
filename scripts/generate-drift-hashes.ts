#!/usr/bin/env tsx

import { writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { openDatabase } from '../src/db.js';
import { buildDriftPayload } from './lib/drift-payload.js';

function main(): void {
  const db = openDatabase(true);
  const payload = buildDriftPayload(db, '0.1.0');

  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);
  const outputPath = join(__dirname, '..', 'fixtures', 'golden-hashes.json');

  writeFileSync(outputPath, `${JSON.stringify(payload, null, 2)}\n`, 'utf-8');

  console.log(`✅ Wrote drift hashes to ${outputPath}`);

  db.close();
}

main();
