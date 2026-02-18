#!/usr/bin/env tsx

import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

interface SourceEntry {
  id: string;
  date: string;
}

function parseSourceDates(raw: string): SourceEntry[] {
  const lines = raw.split(/\r?\n/);
  const entries: SourceEntry[] = [];

  let currentId: string | null = null;

  for (const line of lines) {
    const idMatch = line.match(/^\s*-\s+id:\s+(.+)$/);
    if (idMatch) {
      currentId = idMatch[1].trim();
      continue;
    }

    const dateMatch = line.match(/^\s+data_obtained:\s+"?(\d{4}-\d{2}-\d{2})"?\s*$/);
    if (dateMatch && currentId) {
      entries.push({
        id: currentId,
        date: dateMatch[1],
      });
      currentId = null;
    }
  }

  return entries;
}

function daysBetween(start: Date, end: Date): number {
  const ms = end.getTime() - start.getTime();
  return Math.floor(ms / (1000 * 60 * 60 * 24));
}

function main(): void {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);
  const sourcesPath = join(__dirname, '..', 'sources.yml');
  const thresholdDays = Number(process.env.SOURCE_STALE_THRESHOLD_DAYS || '45');

  const raw = readFileSync(sourcesPath, 'utf-8');
  const entries = parseSourceDates(raw);

  if (entries.length === 0) {
    console.error('No data_obtained entries found in sources.yml');
    process.exit(1);
  }

  const now = new Date();
  const stale = entries
    .map((entry) => ({
      ...entry,
      age_days: daysBetween(new Date(`${entry.date}T00:00:00.000Z`), now),
    }))
    .filter((entry) => entry.age_days > thresholdDays);

  for (const entry of entries) {
    const ageDays = daysBetween(new Date(`${entry.date}T00:00:00.000Z`), now);
    console.log(`${entry.id}: ${entry.date} (${ageDays} days old)`);
  }

  if (stale.length > 0) {
    console.error(`\n❌ ${stale.length} source entries exceed stale threshold (${thresholdDays} days)`);
    for (const entry of stale) {
      console.error(`- ${entry.id}: ${entry.age_days} days`);
    }
    process.exit(1);
  }

  console.log(`\n✅ All source entries are within ${thresholdDays} days.`);
}

main();
