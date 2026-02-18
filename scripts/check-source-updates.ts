#!/usr/bin/env tsx

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

interface SourceEntry {
  id: string;
  date: string;
  authoritativeUrl: string | null;
}

interface LiveCheckResult {
  id: string;
  authoritativeUrl: string;
  reachable: boolean;
  statusCode: number | null;
  lastModified: string | null;
  etag: string | null;
  upstreamNewerDays: number | null;
  error: string | null;
}

function parseSourceEntries(raw: string): SourceEntry[] {
  const lines = raw.split(/\r?\n/);
  const entries: SourceEntry[] = [];

  let currentId: string | null = null;
  let currentDate: string | null = null;
  let currentUrl: string | null = null;

  function flushCurrent(): void {
    if (currentId && currentDate) {
      entries.push({
        id: currentId,
        date: currentDate,
        authoritativeUrl: currentUrl,
      });
    }
    currentId = null;
    currentDate = null;
    currentUrl = null;
  }

  for (const line of lines) {
    const idMatch = line.match(/^\s*-\s+id:\s+(.+)$/);
    if (idMatch) {
      flushCurrent();
      currentId = idMatch[1].trim();
      continue;
    }

    const dateMatch = line.match(/^\s+data_obtained:\s+"?(\d{4}-\d{2}-\d{2})"?\s*$/);
    if (dateMatch) {
      currentDate = dateMatch[1];
      continue;
    }

    const urlMatch = line.match(/^\s+authoritative_url:\s+"?([^"]+)"?\s*$/);
    if (urlMatch) {
      currentUrl = urlMatch[1].trim();
      continue;
    }
  }

  flushCurrent();
  return entries;
}

function daysBetween(start: Date, end: Date): number {
  const ms = end.getTime() - start.getTime();
  return Math.floor(ms / (1000 * 60 * 60 * 24));
}

function parseHeaderDate(value: string | null): Date | null {
  if (!value) {
    return null;
  }
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

async function checkAuthoritativeEndpoint(
  entry: SourceEntry,
  timeoutMs: number,
): Promise<LiveCheckResult | null> {
  if (!entry.authoritativeUrl) {
    return null;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    let response = await fetch(entry.authoritativeUrl, {
      method: 'HEAD',
      redirect: 'follow',
      signal: controller.signal,
    });

    // Some endpoints reject HEAD; fall back to lightweight GET.
    if (!response.ok && response.status === 405) {
      response = await fetch(entry.authoritativeUrl, {
        method: 'GET',
        redirect: 'follow',
        signal: controller.signal,
      });
    }

    const lastModifiedHeader = response.headers.get('last-modified');
    const etagHeader = response.headers.get('etag');
    const sourceDate = new Date(`${entry.date}T00:00:00.000Z`);
    const upstreamDate = parseHeaderDate(lastModifiedHeader);
    const upstreamNewerDays =
      upstreamDate && upstreamDate.getTime() > sourceDate.getTime()
        ? daysBetween(sourceDate, upstreamDate)
        : null;

    return {
      id: entry.id,
      authoritativeUrl: entry.authoritativeUrl,
      reachable: true,
      statusCode: response.status,
      lastModified: lastModifiedHeader,
      etag: etagHeader,
      upstreamNewerDays,
      error: response.ok ? null : `HTTP ${response.status}`,
    };
  } catch (error) {
    return {
      id: entry.id,
      authoritativeUrl: entry.authoritativeUrl,
      reachable: false,
      statusCode: null,
      lastModified: null,
      etag: null,
      upstreamNewerDays: null,
      error: error instanceof Error ? error.message : String(error),
    };
  } finally {
    clearTimeout(timer);
  }
}

async function main(): Promise<void> {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);
  const sourcesPath = join(__dirname, '..', 'sources.yml');
  const thresholdDays = Number(process.env.SOURCE_STALE_THRESHOLD_DAYS || '45');
  const liveCheckEnabled = process.env.SOURCE_LIVE_CHECK === '1';
  const strictLive = process.env.SOURCE_LIVE_CHECK_STRICT === '1';
  const timeoutMs = Number(process.env.SOURCE_LIVE_TIMEOUT_MS || '12000');

  const raw = readFileSync(sourcesPath, 'utf-8');
  const entries = parseSourceEntries(raw);

  if (entries.length === 0) {
    console.error('No data_obtained entries found in sources.yml');
    process.exit(1);
  }

  const now = new Date();
  const staleByDate = entries
    .map((entry) => ({
      ...entry,
      age_days: daysBetween(new Date(`${entry.date}T00:00:00.000Z`), now),
    }))
    .filter((entry) => entry.age_days > thresholdDays);

  for (const entry of entries) {
    const ageDays = daysBetween(new Date(`${entry.date}T00:00:00.000Z`), now);
    console.log(`${entry.id}: ${entry.date} (${ageDays} days old)`);
  }

  const liveResults: LiveCheckResult[] = [];
  if (liveCheckEnabled) {
    for (const entry of entries) {
      const result = await checkAuthoritativeEndpoint(entry, timeoutMs);
      if (!result) {
        continue;
      }
      liveResults.push(result);
      const status = result.reachable ? `HTTP ${result.statusCode}` : `unreachable (${result.error})`;
      const recency = result.upstreamNewerDays !== null ? `, upstream newer by ${result.upstreamNewerDays} days` : '';
      console.log(`live:${result.id}: ${status}${recency}`);
    }
  }

  const staleByUpstream = liveResults.filter((result) => (result.upstreamNewerDays ?? 0) > 0);
  const unreachable = liveResults.filter((result) => !result.reachable);

  if (staleByDate.length > 0) {
    console.error(`\n❌ ${staleByDate.length} source entries exceed stale threshold (${thresholdDays} days)`);
    for (const entry of staleByDate) {
      console.error(`- ${entry.id}: ${entry.age_days} days`);
    }
    process.exit(1);
  }

  if (strictLive && unreachable.length > 0) {
    console.error(`\n❌ ${unreachable.length} authoritative endpoints were unreachable in strict mode`);
    for (const entry of unreachable) {
      console.error(`- ${entry.id}: ${entry.authoritativeUrl} (${entry.error ?? 'unknown error'})`);
    }
    process.exit(1);
  }

  if (staleByUpstream.length > 0) {
    const level = strictLive ? '❌' : '⚠️';
    console.error(`\n${level} ${staleByUpstream.length} sources appear older than authoritative endpoint metadata`);
    for (const entry of staleByUpstream) {
      console.error(`- ${entry.id}: upstream newer by ${entry.upstreamNewerDays} day(s)`);
    }
    if (strictLive) {
      process.exit(1);
    }
  }

  console.log(`\n✅ Source freshness checks passed (threshold ${thresholdDays} days).`);
}

main().catch((error) => {
  console.error(`❌ Source freshness check failed: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});
