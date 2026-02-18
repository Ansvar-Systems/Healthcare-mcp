import { createHash } from 'node:crypto';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';
import type { AboutContext } from './types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const SOURCE_DB_PATH = join(__dirname, '..', 'data', 'healthcare.db');
const DIST_DB_PATH = join(__dirname, '..', '..', 'data', 'healthcare.db');

export const DB_PATH = process.env.HEALTHCARE_MCP_DB_PATH ||
  (existsSync(SOURCE_DB_PATH) ? SOURCE_DB_PATH : DIST_DB_PATH);

export interface SqlStatement {
  all: (...params: unknown[]) => unknown[];
  get: (...params: unknown[]) => unknown;
  run: (...params: unknown[]) => unknown;
}

export interface SqlDatabase {
  prepare: (sql: string) => SqlStatement;
  exec: (sql: string) => void;
  close: () => void;
}

class NodeSqliteDatabase implements SqlDatabase {
  private readonly database: DatabaseSync;

  constructor(path: string, readonly: boolean) {
    this.database = new DatabaseSync(path, { readOnly: readonly });
  }

  prepare(sql: string): SqlStatement {
    const statement = this.database.prepare(sql);
    return {
      all: (...params: unknown[]) => statement.all(...(params as any[])),
      get: (...params: unknown[]) => statement.get(...(params as any[])),
      run: (...params: unknown[]) => statement.run(...(params as any[])),
    };
  }

  exec(sql: string): void {
    this.database.exec(sql);
  }

  close(): void {
    this.database.close();
  }
}

export function openDatabase(readonly = true): SqlDatabase {
  return new NodeSqliteDatabase(DB_PATH, readonly);
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
