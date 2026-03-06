import type { SqlDatabase } from '../db.js';

interface SearchRow {
  content_type: string;
  source_id: string;
  title: string;
  snippet: string;
  relevance_score: number;
}

function sanitizeQuery(query: string): string {
  return query.replace(/[^a-zA-Z0-9\s]/g, ' ').trim().replace(/\s+/g, ' ');
}

function parseCursor(cursor: string | undefined): number {
  if (!cursor) {
    return 0;
  }
  try {
    const decoded = Buffer.from(cursor, 'base64url').toString('utf-8');
    const offset = Number.parseInt(decoded, 10);
    return Number.isFinite(offset) && offset >= 0 ? offset : 0;
  } catch {
    return 0;
  }
}

function encodeCursor(offset: number): string {
  return Buffer.from(String(offset), 'utf-8').toString('base64url');
}

export function searchDomainKnowledge(db: SqlDatabase, args: unknown) {
  const input = (args ?? {}) as {
    query?: string;
    content_type?: 'threat' | 'architecture' | 'standards' | 'all';
    limit?: number;
    cursor?: string;
  };

  if (!input.query || input.query.trim().length < 2) {
    return {
      error: 'query is required and must be at least 2 characters',
      hint: 'Use a healthcare term like FHIR, DICOM, ransomware, or telehealth.',
    };
  }

  const clean = sanitizeQuery(input.query);
  if (!clean) {
    return {
      error: 'query is empty after sanitization',
      hint: 'Avoid only punctuation or special symbols.',
    };
  }

  const limit = Math.max(1, Math.min(50, input.limit ?? 10));
  const contentType = input.content_type ?? 'all';
  const offset = parseCursor(input.cursor);
  const fetchWindow = offset + limit + 1;

  const results: SearchRow[] = [];

  if (contentType === 'all' || contentType === 'threat') {
    const threatRows = db
      .prepare(
        `SELECT 'threat' as content_type,
                t.threat_id as source_id,
                t.name as title,
                snippet(threat_scenarios_fts, 2, '<b>', '</b>', '...', 20) as snippet,
                bm25(threat_scenarios_fts) as relevance_score
         FROM threat_scenarios_fts
         JOIN threat_scenarios t ON t.rowid = threat_scenarios_fts.rowid
         WHERE threat_scenarios_fts MATCH ?
         ORDER BY relevance_score ASC
         LIMIT ?`,
      )
      .all(clean, fetchWindow) as SearchRow[];

    results.push(...threatRows);
  }

  if (contentType === 'all' || contentType === 'architecture') {
    const architectureRows = db
      .prepare(
        `SELECT 'architecture' as content_type,
                a.pattern_id as source_id,
                a.name as title,
                snippet(architecture_patterns_fts, 2, '<b>', '</b>', '...', 18) as snippet,
                bm25(architecture_patterns_fts) as relevance_score
         FROM architecture_patterns_fts
         JOIN architecture_patterns a ON a.rowid = architecture_patterns_fts.rowid
         WHERE architecture_patterns_fts MATCH ?
         ORDER BY relevance_score ASC
         LIMIT ?`,
      )
      .all(clean, fetchWindow) as SearchRow[];

    results.push(...architectureRows);
  }

  if (contentType === 'all' || contentType === 'standards') {
    const standardRows = db
      .prepare(
        `SELECT 'standards' as content_type,
                s.standard_id as source_id,
                s.name as title,
                snippet(technical_standards_fts, 3, '<b>', '</b>', '...', 18) as snippet,
                bm25(technical_standards_fts) as relevance_score
         FROM technical_standards_fts
         JOIN technical_standards s ON s.rowid = technical_standards_fts.rowid
         WHERE technical_standards_fts MATCH ?
         ORDER BY relevance_score ASC
         LIMIT ?`,
      )
      .all(clean, fetchWindow) as SearchRow[];

    results.push(...standardRows);
  }

  const sorted = results.sort((a, b) => a.relevance_score - b.relevance_score);
  const pagedWindow = sorted.slice(offset, offset + limit + 1);
  const hasMore = pagedWindow.length > limit;
  const pagedResults = hasMore ? pagedWindow.slice(0, limit) : pagedWindow;
  const nextOffset = offset + pagedResults.length;

  return {
    query: input.query,
    content_type: contentType,
    limit,
    cursor: input.cursor ?? null,
    scope_status: pagedResults.length > 0 ? 'in_scope' : 'not_indexed',
    results: pagedResults,
    pagination: {
      next_cursor: hasMore ? encodeCursor(nextOffset) : null,
      offset,
      returned: pagedResults.length,
    },
  };
}
