export const DATA_AGE = '2026-02-18';

export const SOURCE_URL = 'https://github.com/Ansvar-Systems/Healthcare-mcp';

export const DISCLAIMER =
  'Healthcare Intelligence MCP provides domain-intelligence metadata for threat modeling and regulatory awareness. It does not constitute legal advice or authoritative regulatory guidance. Validate obligations and control requirements through upstream authoritative MCPs before relying on outputs for compliance decisions.';

export interface ResponseMeta {
  _meta: {
    disclaimer: string;
    data_age: string;
    source_url: string;
  };
}

export function responseMeta(): ResponseMeta {
  return {
    _meta: {
      disclaimer: DISCLAIMER,
      data_age: DATA_AGE,
      source_url: SOURCE_URL,
    },
  };
}
