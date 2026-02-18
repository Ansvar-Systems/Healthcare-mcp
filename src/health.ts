import type { SqlDatabase } from './db.js';

export interface HealthPayload {
  status: 'ok' | 'stale' | 'degraded';
  database: 'available' | 'unavailable';
  source_freshness_days: number | null;
  build_age_days: number | null;
  stale_threshold_days: number;
}

function daysSince(value: string): number | null {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return null;
  }
  const diffMs = Date.now() - parsed.getTime();
  return Math.floor(diffMs / (1000 * 60 * 60 * 24));
}

function getMeta(db: SqlDatabase, key: string): string | null {
  const row = db.prepare('SELECT value FROM db_metadata WHERE key = ?').get(key) as
    | { value: string }
    | undefined;
  return row?.value ?? null;
}

export function getHealthPayload(db: SqlDatabase, staleThresholdDays: number): HealthPayload {
  try {
    db.prepare('SELECT 1').get();
  } catch {
    return {
      status: 'degraded',
      database: 'unavailable',
      source_freshness_days: null,
      build_age_days: null,
      stale_threshold_days: staleThresholdDays,
    };
  }

  const sourceCheck = getMeta(db, 'last_source_check');
  const builtAt = getMeta(db, 'built_at');
  const sourceAge = sourceCheck ? daysSince(sourceCheck) : null;
  const buildAge = builtAt ? daysSince(builtAt) : null;
  const isStale =
    (sourceAge !== null && sourceAge > staleThresholdDays) ||
    (buildAge !== null && buildAge > staleThresholdDays);

  return {
    status: isStale ? 'stale' : 'ok',
    database: 'available',
    source_freshness_days: sourceAge,
    build_age_days: buildAge,
    stale_threshold_days: staleThresholdDays,
  };
}
