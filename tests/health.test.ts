import { describe, expect, it } from 'vitest';
import { openDatabase } from '../src/db.js';
import { getHealthPayload } from '../src/health.js';

describe('health payload status', () => {
  const db = openDatabase(true);

  it('returns ok when source freshness is within threshold', () => {
    const payload = getHealthPayload(db, 45);
    expect(payload.status).toBe('ok');
    expect(payload.database).toBe('available');
  });

  it('returns stale when threshold is exceeded', () => {
    const payload = getHealthPayload(db, -1);
    expect(payload.status).toBe('stale');
  });
});
