# M3.5 Validation Gate

**Date:** 2026-04-27  
**Branch:** `codex/m3-confidence-timeouts`  
**Scope:** M3.1-M3.4 scanner behavior before starting M3.5 behavioral supply-chain analysis.

## Verification

Baseline checks passed before this validation note:

- `./node_modules/.bin/vitest run` - 268 tests passed
- `./node_modules/.bin/tsc --noEmit` - passed
- `./node_modules/.bin/tsc` - passed

`npm` was not available on this shell PATH, so validation used repo-local binaries and `./node_modules/.bin/tsx` for CLI smoke checks.

## Scan Targets

| Target | Default findings | Severity mix | Main rules |
| --- | ---: | --- | --- |
| `/Users/vincent/Developer/Github/personal/attestlens` | 32 | 10 critical, 2 high, 20 medium | `VS-XSS`, `VS-HARDKEY`, `VS-PUBLIC-SECRET-ENV` |
| `/Users/vincent/Developer/Github/personal/strands` | 316 | 12 critical, 223 high, 81 medium | `VS-SQLI`, `VS-DEBUG`, `VS-XSS` |
| `/Users/vincent/Developer/Github/personal/bgm-cafe` | 0 | none | none |
| `/Users/vincent/Developer/Github/explore/paperclip` | 207 | 25 critical, 136 high, 46 medium | `VS-SQLI`, `VS-XSS`, `VS-HARDKEY` |
| `/Users/vincent/Developer/Github/explore/multica` | 8 | 8 medium | `VS-XSS` |

Additional regressions:

- External enrichment scan on `attestlens`: 32 findings, matching the default scan count in this local pass.
- Explicit typosquat opt-in scan on `attestlens`: 32 findings, no `VS-SC-004` false-positive expansion in this local pass.
- CLI smoke on `bgm-cafe`: completed in 1.1s with no findings.

Structured report payloads for this run were written outside the repo at `/tmp/attestlens-validation-m3-5-gate`.

## Findings

- No P0/P1 finding-corruption issue was found. Reports still map findings to `APP_6`, `APP_11`, and `NDB` where expected.
- GuardVibe remains unavailable from npm as `@guardvibe/cli`, and the adapter correctly falls back to embedded static checks with a recoverable warning.
- The installed `mcp-scan` command rejects the current `--path` invocation shape, and the adapter correctly skips with a recoverable warning.
- Path scans were invoking `url-scan` and showing `INVALID_URL`. This validation slice fixes orchestrator routing so URL scanning only runs by default for HTTP(S) targets.
- The largest current credibility risk is scanner noise from broad fallback rules (`VS-SQLI`, `VS-XSS`, `VS-HARDKEY`) on large repos. This does not block M3.5, but M3.7 SAST-lite should stay conservative to avoid adding more noise.

## Gate Decision

M3.5 may proceed after the URL-scan routing fix and validation-note commit. The validation pass did not show a blocker that invalidates M3.1-M3.4 or the report schema.
