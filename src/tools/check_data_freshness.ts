import type { SqlDatabase } from '../db.js';
import { DATA_AGE, responseMeta } from './response-meta.js';

const STALE_THRESHOLD_DAYS = 45;

function daysBetween(dateA: string, dateB: string): number {
  const msPerDay = 1000 * 60 * 60 * 24;
  return Math.floor((Date.parse(dateB) - Date.parse(dateA)) / msPerDay);
}

export function checkDataFreshness(db: SqlDatabase, _args: unknown): Record<string, unknown> {
  const metadataRows = db
    .prepare('SELECT key, value FROM db_metadata ORDER BY key')
    .all() as Array<{ key: string; value: string }>;

  const metadata = Object.fromEntries(metadataRows.map((row) => [row.key, row.value]));

  const builtAt: string = (metadata.built_at as string) ?? DATA_AGE;
  const lastSourceCheck: string = (metadata.last_source_check as string) ?? DATA_AGE;
  const today = new Date().toISOString().slice(0, 10);

  const daysSinceBuilt = daysBetween(builtAt.slice(0, 10), today);
  const daysSinceSourceCheck = daysBetween(lastSourceCheck.slice(0, 10), today);

  const isStale = daysSinceSourceCheck > STALE_THRESHOLD_DAYS;

  return {
    freshness_status: isStale ? 'stale' : 'current',
    built_at: builtAt,
    last_source_check: lastSourceCheck,
    days_since_built: daysSinceBuilt,
    days_since_source_check: daysSinceSourceCheck,
    stale_threshold_days: STALE_THRESHOLD_DAYS,
    db_metadata: metadata,
    guidance: isStale
      ? 'Data has exceeded the staleness threshold. Re-run the check-source-updates workflow or update db_metadata.last_source_check if sources have been confirmed current.'
      : 'Data is within the freshness threshold. No immediate action required.',
    ...responseMeta(),
  };
}
