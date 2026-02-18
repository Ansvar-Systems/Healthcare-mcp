# Healthcare MCP Remediation Audit

- **Date:** 2026-02-18
- **Scope:** Closure pass for findings from `2026-02-18-production-audit.md`

## Status

| Finding | Prior State | Current State |
|---|---|---|
| Runtime SQLite portability | FAIL (`better-sqlite3` runtime coupling) | **Closed** (`src/db.ts` now uses a serverless-safe SQLite adapter over `node:sqlite`; `better-sqlite3` removed from dependencies) |
| Missing schema examples | WARNING | **Closed** (examples now injected for all tools via `tools/list`) |
| No detail-level controls | WARNING | **Closed** (`detail_level` in `get_healthcare_threats` and `assess_healthcare_applicability`) |
| No pagination on key search tools | WARNING | **Closed** (cursor pagination added to `search_domain_knowledge` and `get_healthcare_threats`) |
| LIKE search on architecture/standards | WARNING | **Closed** (FTS5 indexes + `MATCH` query paths) |
| Static-only source freshness check | WARNING | **Closed** (optional live authoritative endpoint checks with strict mode) |
| Release pipeline missing strict upstream gate | WARNING | **Closed** (`publish.yml` now enforces strict live upstream tests + release integrity checks) |
| Coverage gate gap | WARNING | **Closed** (`test:coverage` canonical tool-coverage gate wired into `test:ci`) |
| Scope ambiguity (`in_scope` vs `not_indexed`) | WARNING | **Closed** (`scope_status` added across high-value routing/search outputs) |
| Release metadata drift risk | WARNING | **Closed** (`scripts/verify-release-integrity.ts` + publish gating) |

## Validation Evidence

- `npm run test:ci` passed (`58` tests passed, `3` skipped live tests).
- `npm run check:source-updates` passed.
- `npm run verify:release` passed.
- `npm pack --dry-run` passed.

## Residual Notes

- Local `npm audit` is still blocked in this environment by DNS/network constraints (`ENOTFOUND registry.npmjs.org`), but release workflow now performs stricter integrity checks and still runs full CI gates before publish.
