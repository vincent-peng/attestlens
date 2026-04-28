# M3.8-M3.10 Validation Gate

- Date: 2026-04-28
- Validation pass commit: `38992e2`
- Post-review scanner fallout fix: `11ab57c`
- Raw local artifacts: `/tmp/attestlens-m3-8-10-validation-final-2026-04-28T10-49-41-751Z`
- Public corpus artifacts: `attestlens-reports/validation/2026-04-28` (gitignored)

## Result

M3.8-M3.10 is acceptable for scanner closeout after two validation-fallout fixes:

- `7f62ac2` reduced static/SAST report noise from tests, fixtures, hidden worktrees, and safe ORM SQL templates.
- `38992e2` stopped IaC scanning hidden worktrees and prevented secret resolver identifiers from being reported as hardcoded secrets.
- `11ab57c` fixed post-review scanner fallout around real hidden config paths, context-aware `VS-HARDKEY` matching, and embedded rule-pack metadata.

No remaining P0/P1 issue was found in the final local validation pass after the original fallout fixes; the subsequent review-found scanner regressions were fixed in `11ab57c`. Dashboard/SaaS work should still wait for design-partner review of the refreshed report shape.

## Local Project Gate

Default scan and audit were run against the five requested local projects.

| Repo | Scan exit | Scan findings | Audit exit | Report findings | Grade | Risk | IaC | Maturity | Corroborated | Warnings |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| AttestLens | 0 | 19 | 2 | 19 | C | critical | 0 | 0 | 0 | `GUARDVIBE_UNAVAILABLE`, `MCP_SCAN_UNAVAILABLE` |
| Strands | 0 | 83 | 2 | 83 | C | critical | 4 | 0 | 0 | `GUARDVIBE_UNAVAILABLE`, `MCP_SCAN_UNAVAILABLE` |
| bgm-cafe | 0 | 1 | 1 | 1 | A | low | 0 | 0 | 0 | `GUARDVIBE_UNAVAILABLE`, `MCP_SCAN_UNAVAILABLE` |
| Paperclip | 0 | 96 | 2 | 96 | C | critical | 8 | 0 | 0 | `GUARDVIBE_UNAVAILABLE`, `MCP_SCAN_UNAVAILABLE` |
| Multica | 0 | 16 | 1 | 16 | B | medium | 2 | 0 | 0 | `GUARDVIBE_UNAVAILABLE`, `MCP_SCAN_UNAVAILABLE` |

Notes:

- No `SCANNER_TIMEOUT` occurred.
- Audit exits `1`/`2` are expected when failing controls or critical findings exist.
- `GuardVibe` and `mcp-scan` external binaries were unavailable locally, but both degraded through recoverable warnings and static fallback.
- Remaining Strands/Paperclip volume is mostly SAST review backlog in production source paths: CSRF visibility, localStorage usage, sensitive logging, and mutation-route validation. The hidden worktree/test-fixture inflation from the first pass was removed.

## Scenario Checks

| Scenario | Result |
|---|---|
| External enrichment | Completed on AttestLens with scan exit `0`; emitted no `VS-SC-010` or OSV findings. One recoverable `NPM_MATURITY_ERROR` occurred for `zod` because the registry response exceeded the 1 MB guard. |
| Typosquat opt-in | Completed on AttestLens with scan exit `0`; emitted no `VS-SC-004`, so no `EXPERIMENTAL_TYPOSQUAT` warning was expected. |
| `--no-iac` comparison | Completed on Strands; findings dropped from `83` to `79`, confirming IaC findings were removable by the public flag. |
| Gitleaks opt-in | Skipped because `gitleaks` was not installed in `PATH`. |
| Cross-scanner corroboration | No live `corroboratedBy` merge occurred in these repos; unit coverage remains the proof point for this behavior. |

## Public Corpus

`npm run validate:corpus` was rerun on `38992e2`.

| Target | Status | Findings | Grade | Risk |
|---|---:|---:|---:|---:|
| Example | passed | 10 | A | medium |
| Supabase | failed | 0 | - | - |
| Firebase | passed | 7 | A | medium |
| Vercel | passed | 42 | B | low |
| Netlify | passed | 11 | A | medium |
| Clerk | failed | 0 | - | - |
| Auth0 | passed | 14 | A | medium |
| Stripe | passed | 10 | A | low |
| OWASP Juice Shop | passed | 11 | A | medium |

Supabase and Clerk failed at URL scan startup with `URL scan failed before findings could be collected`. They passed earlier in this round on the same date before path-only scanner noise fixes. Treat this as known live-site/CDN instability, not an M3.8-M3.10 path-scanner blocker.

## Follow-Up

- Keep M4/dashboard blocked until design partners review refreshed M2/M3 reports.
- Consider a P2 URL-corpus hardening pass for live-site startup failures and better blocked-target notes.
- Consider a P2 report-summary pass so self-scans of AttestLens do not overemphasize scanner rule source files.
- Install `gitleaks` in a validation environment before claiming history-scan coverage on real projects.
