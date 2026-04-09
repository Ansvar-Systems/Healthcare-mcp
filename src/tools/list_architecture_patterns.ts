import type { SqlDatabase } from '../db.js';
import { responseMeta } from './response-meta.js';

export function listArchitecturePatterns(db: SqlDatabase, args: unknown) {
  const input = (args ?? {}) as { category?: string };

  const rows = input.category
    ? db
        .prepare(
          `SELECT pattern_id, name, description, primary_system
           FROM architecture_patterns
           WHERE lower(primary_system) = lower(?)
           ORDER BY pattern_id`,
        )
        .all(input.category)
    : db
        .prepare(
          `SELECT pattern_id, name, description, primary_system
           FROM architecture_patterns
           ORDER BY pattern_id`,
        )
        .all();

  return {
    pattern_count: rows.length,
    patterns: rows,
    ...responseMeta(),
  };
}
