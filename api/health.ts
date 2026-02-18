import type { VercelRequest, VercelResponse } from '@vercel/node';
import { openDatabase } from '../src/db.js';
import { getHealthPayload } from '../src/health.js';

const db = openDatabase(true);

export default function handler(_req: VercelRequest, res: VercelResponse): void {
  const staleThresholdDays = Number(process.env.HEALTHCARE_STALE_DAYS ?? '45');
  const payload = getHealthPayload(db, staleThresholdDays);

  res.status(payload.status === 'degraded' ? 503 : 200).json({
    status: payload.status,
    server: 'healthcare-mcp',
    database: payload.database,
    source_freshness_days: payload.source_freshness_days,
    build_age_days: payload.build_age_days,
    stale_threshold_days: payload.stale_threshold_days,
  });
}
