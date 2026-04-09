import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { responseMeta } from './response-meta.js';

interface SourceEntry {
  id: string;
  name?: string;
  type?: string;
  authority?: string;
  authoritative_url?: string;
  license?: string;
  update_frequency?: string;
  data_obtained?: string;
  [key: string]: string | undefined;
}

function stripQuotes(value: string): string {
  const trimmed = value.trim();
  if ((trimmed.startsWith('"') && trimmed.endsWith('"')) || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function resolveSourcesPath(): string {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);

  const candidates = [
    join(__dirname, '..', '..', 'sources.yml'),
    join(__dirname, '..', '..', '..', 'sources.yml'),
  ];

  const found = candidates.find((candidate) => existsSync(candidate));
  if (!found) {
    throw new Error('sources.yml not found in expected runtime locations');
  }

  return found;
}

function parseSources(raw: string): SourceEntry[] {
  const lines = raw.split(/\r?\n/);
  const entries: SourceEntry[] = [];
  let current: SourceEntry | null = null;

  for (const line of lines) {
    const idMatch = line.match(/^\s*-\s+id:\s+(.+)$/);
    if (idMatch) {
      if (current?.id) {
        entries.push(current);
      }
      current = { id: stripQuotes(idMatch[1]) };
      continue;
    }

    if (!current) {
      continue;
    }

    const kvMatch = line.match(/^\s+([a-zA-Z0-9_]+):\s+(.+)$/);
    if (kvMatch) {
      const key = kvMatch[1];
      const value = stripQuotes(kvMatch[2]);
      current[key] = value;
    }
  }

  if (current?.id) {
    entries.push(current);
  }

  return entries;
}

export function listSources(_db: unknown, args: unknown) {
  const input = (args ?? {}) as { source_type?: string };
  const sourcesPath = resolveSourcesPath();
  const sources = parseSources(readFileSync(sourcesPath, 'utf-8'));

  const filtered = input.source_type
    ? sources.filter((source) => source.type === input.source_type)
    : sources;

  return {
    source_count: filtered.length,
    sources: filtered.map((source) => ({
      id: source.id,
      name: source.name ?? null,
      source_type: source.type ?? null,
      authority: source.authority ?? null,
      source_url: source.authoritative_url ?? null,
      license: source.license ?? null,
      data_method: source.data_method ?? null,
      content_scope: source.content_scope ?? null,
      refresh_cadence: source.update_frequency ?? null,
      last_obtained: source.data_obtained ?? null,
    })),
    ...responseMeta(),
  };
}
