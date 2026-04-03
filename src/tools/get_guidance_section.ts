import type { SqlDatabase } from '../db.js';

interface GuidanceSection {
  section_id: string;
  document_id: string;
  heading: string;
  content: string;
  word_count: number;
}

interface GuidanceDocument {
  document_id: string;
  title: string;
  authority: string;
  version: string;
  document_type: string;
  url: string | null;
}

export function getGuidanceSection(db: SqlDatabase, args: unknown) {
  const input = (args ?? {}) as { section_id?: string; document_id?: string };

  if (input.section_id) {
    const row = db
      .prepare('SELECT * FROM regulatory_guidance WHERE section_id = ?')
      .get(input.section_id) as GuidanceSection | undefined;

    if (!row) {
      return { error: `Section '${input.section_id}' not found` };
    }

    const doc = db
      .prepare('SELECT * FROM regulatory_guidance_documents WHERE document_id = ?')
      .get(row.document_id) as GuidanceDocument | undefined;

    return { section: row, document: doc ?? null };
  }

  if (input.document_id) {
    const doc = db
      .prepare('SELECT * FROM regulatory_guidance_documents WHERE document_id = ?')
      .get(input.document_id) as GuidanceDocument | undefined;

    if (!doc) {
      return { error: `Document '${input.document_id}' not found` };
    }

    const sections = db
      .prepare('SELECT section_id, heading, word_count FROM regulatory_guidance WHERE document_id = ? ORDER BY rowid')
      .all(input.document_id) as Array<{ section_id: string; heading: string; word_count: number }>;

    return { document: doc, sections };
  }

  // List all documents
  const docs = db
    .prepare('SELECT * FROM regulatory_guidance_documents ORDER BY authority, document_id')
    .all() as GuidanceDocument[];

  return {
    documents: docs,
    total_sections: (db.prepare('SELECT COUNT(*) as count FROM regulatory_guidance').get() as { count: number }).count,
  };
}
