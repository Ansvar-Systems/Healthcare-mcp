import Database from 'better-sqlite3';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AboutContext } from './types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const SOURCE_DB_PATH = join(__dirname, '..', 'data', 'healthcare.db');
const DIST_DB_PATH = join(__dirname, '..', '..', 'data', 'healthcare.db');

export const DB_PATH = process.env.HEALTHCARE_MCP_DB_PATH ||
  (existsSync(SOURCE_DB_PATH) ? SOURCE_DB_PATH : DIST_DB_PATH);

export function openDatabase(readonly = true): Database.Database {
  return new Database(DB_PATH, { readonly });
}

export function computeAboutContext(version: string): AboutContext {
  let fingerprint = 'unknown';
  let dbBuilt = new Date().toISOString();

  try {
    const dbBytes = readFileSync(DB_PATH);
    fingerprint = createHash('sha256').update(dbBytes).digest('hex').slice(0, 12);
    dbBuilt = statSync(DB_PATH).mtime.toISOString();
  } catch {
    // Non-fatal for startup; surfaced by about tool.
  }

  return {
    version,
    fingerprint,
    dbBuilt,
  };
}

export function parseJsonArray(value: string | null): string[] {
  if (!value) {
    return [];
  }

  try {
    const parsed = JSON.parse(value) as unknown;
    return Array.isArray(parsed) ? parsed.map((item) => String(item)) : [];
  } catch {
    return [];
  }
}
