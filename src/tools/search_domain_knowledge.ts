import type Database from 'better-sqlite3';

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

export function searchDomainKnowledge(db: Database.Database, args: unknown) {
  const input = (args ?? {}) as {
    query?: string;
    content_type?: 'threat' | 'architecture' | 'standards' | 'all';
    limit?: number;
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

  if (/(automotive|ecu|vehicle|iso\\s*21434|unece\\s*r155)/i.test(input.query)) {
    return {
      query: input.query,
      content_type: contentType,
      limit,
      results: [],
      out_of_scope: [
        'Query appears to target automotive cybersecurity. Use Automotive MCP for that domain.',
      ],
      recommended_mcp: 'Automotive-MCP',
    };
  }

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
      .all(clean, limit) as SearchRow[];

    results.push(...threatRows);
  }

  if (contentType === 'all' || contentType === 'architecture') {
    const archRows = db
      .prepare(
        `SELECT 'architecture' as content_type,
                pattern_id as source_id,
                name as title,
                description as snippet,
                0.5 as relevance_score
         FROM architecture_patterns
         WHERE lower(name) LIKE lower(?) OR lower(description) LIKE lower(?)
         LIMIT ?`,
      )
      .all(`%${clean}%`, `%${clean}%`, limit) as SearchRow[];

    results.push(...archRows);
  }

  if (contentType === 'all' || contentType === 'standards') {
    const standardRows = db
      .prepare(
        `SELECT 'standards' as content_type,
                standard_id as source_id,
                name as title,
                scope as snippet,
                0.6 as relevance_score
         FROM technical_standards
         WHERE lower(name) LIKE lower(?) OR lower(scope) LIKE lower(?)
         LIMIT ?`,
      )
      .all(`%${clean}%`, `%${clean}%`, limit) as SearchRow[];

    results.push(...standardRows);
  }

  const sorted = results
    .sort((a, b) => a.relevance_score - b.relevance_score)
    .slice(0, limit);

  return {
    query: input.query,
    content_type: contentType,
    limit,
    results: sorted,
  };
}
