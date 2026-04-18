# AttestLens — Security Audit (April 18, 2026)

Comprehensive security audit performed after validation scans and code review.

## CRITICAL Issues (2 — FIXED)

### C-01: npm audit blocks event loop ✅ FIXED
- **File:** `src/scanner/supply-chain.ts:478-510`
- **Was:** `execFileSync('npm', ['audit', '--json'])` blocks Node.js event loop for up to 30 seconds
- **Risk:** DoS vector — concurrent scans could starve the event loop; no way to cancel
- **Fix:** Replaced with `promisify(execFile)` + `AbortController` with 30s timeout
- **Added:** `node_modules` existence check before running npm audit (skips silently on fresh clones)

### C-02: MCP server path traversal ✅ FIXED
- **File:** `src/mcp/index.ts:33-58`
- **Was:** `validatePath()` accepted any directory path on the system
- **Risk:** MCP client could scan `/etc`, `/root`, or any sensitive directory
- **Fix:** Added `ALLOWED_ROOTS` restriction (defaults to `process.cwd()`, configurable via `ATTESTLENS_ALLOWED_ROOTS` env var)
- **Added:** Unit tests for path traversal prevention (6 tests)

## IMPORTANT Issues (4 — OPEN)

### I-01: `any` types in MCP server arguments
- **File:** `src/mcp/index.ts:216,221`
- **Problem:** `args?.findings as Array<any>` and `rawFindings.map((f: any, ...) => ...)` — MCP tool arguments are loosely typed
- **Risk:** Invalid/malformed findings could cause runtime errors or unexpected behavior
- **Fix:** Define Zod schemas for incoming findings and validate before processing
- **Effort:** Medium

### I-02: `any` types in CLI Commander options
- **File:** `src/cli/index.ts:41,138,260`
- **Problem:** `options: any` for all three commands (scan, audit, report)
- **Risk:** Typo in option names (`options.format` vs `options.formats`) would silently fail
- **Fix:** Define typed option interfaces per command
- **Effort:** Low

### I-03: npm audit requires installed `node_modules`
- **File:** `src/scanner/supply-chain.ts:466-469`
- **Problem:** `npm audit` only works when `node_modules` exists. On fresh clones or CI, it fails.
- **Current behavior:** Now checks for `node_modules` and skips silently
- **Remaining:** Should note this in documentation and possibly in the scan output
- **Effort:** Low

### I-04: Lockfile finding false positive on shallow clones
- **File:** `src/scanner/supply-chain.ts:VS-SC-005`
- **Problem:** `git clone --depth 1` doesn't include `package-lock.json`, so every shallow clone gets a "Missing lockfile" critical finding
- **Fix options:**
  - Detect `.git` directory and add note about shallow clones
  - Lower severity from critical to medium when `.git` exists but lockfile doesn't
  - Add `--no-lockfile-check` flag
- **Effort:** Medium

## Security Analysis by Module

### Supply Chain Scanner (`src/scanner/supply-chain.ts`)
- ✅ Path validation uses `path.resolve()` + `fs.stat()` to prevent traversal
- ✅ No string interpolation in shell commands (uses `execFile` with args array)
- ✅ Typosquat detection properly checks popular package membership before Levenshtein comparison
- ✅ Scoped packages from well-known orgs bypass typosquat checks
- ✅ npm audit uses async execution with AbortController
- ⚠️ `findSourceFiles()` doesn't respect `.gitignore` — could scan `dist/` or `build/` for imports
- ⚠️ Levenshtein distance O(n²) on long strings — could be slow on packages with very long names (negligible risk)
- ℹ️ `levenshteinDistance` implementation is correct but allocates a full matrix — could use two-row optimization for memory

### MCP Server (`src/mcp/index.ts`)
- ✅ Path traversal prevention with ALLOWED_ROOTS
- ✅ Suspicious character rejection (`/[;|`$\\]/`)
- ✅ Directory existence check
- ✅ Proper McpError usage for all error paths
- ✅ Tool definitions have proper inputSchema
- ⚠️ No rate limiting — a malicious client could spam scan requests
- ⚠️ No authentication — relies on MCP transport security (stdio)
- ℹ️ `args` types are `any` — should use Zod validation for robustness

### CLI (`src/cli/index.ts`)
- ✅ Path validation with `path.resolve()` + `fs.stat()`
- ✅ Proper error handling with try/catch
- ✅ Non-zero exit codes for critical findings (2) and fail controls (1)
- ⚠️ `process.exit()` in catch blocks — hard to test, could leave resources unclosed
- ℹ️ No `--quiet` or `--json` flag for `scan` command (only `audit` has format options)

### Mapping Engine (`src/mapping/engine.ts`)
- ✅ 25 mapping rules covering APP 1, 6, 8, 11, 12, NDB
- ✅ Confidence-weighted mappings (0.40-0.97)
- ✅ OAIC guideline references for each rule
- ✅ Severity-based score deductions (critical=15, high=10, medium=5, low=2, info=1)
- ✅ Strict mode converts UNKNOWN → FAIL
- ⚠️ APP 3, 5, 10, 13 only get mappings via "default bucket" (APP 11) for high/critical findings
- ⚠️ Some rules have low confidence (0.50-0.55) — could generate false PASS/UNKNOWN
- ℹ️ Missing explicit rules for APP 2, 4, 7, 9 (these are questionnaire-only principles)

### Report Generator (`src/report/generator.ts`)
- ✅ Grade calculation: A (90+), B (75-89), C (60-74), D (40-59), F (<40)
- ✅ Risk level: critical (any critical), high (any high), medium (any medium), low (otherwise)
- ✅ Remediation items with priority ordering
- ✅ Professional HTML report with disclaimer
- ⚠️ No PDF generation yet (Phase 2)
- ℹ️ HTML report styling is functional but plain — consultants will compare to Big 4 templates

### Orchestrator (`src/scanner/orchestrator.ts`)
- ✅ Parallel scanner execution with `Promise.allSettled`
- ✅ Graceful error handling — one scanner failing doesn't block others
- ✅ Finding deduplication by `sourceRule:file:line`
- ⚠️ No retry logic for transient scanner failures
- ⚠️ No progress reporting (spinner shows total duration, not per-scanner)

## Positive Observations

1. **Clean module architecture** — Scanner/Mapper/Report/Questionnaire/MCP/CLI each have clear responsibilities
2. **Zod schema throughout** — Finding and compliance types are properly validated
3. **Security-first design** — Path validation in both CLI and MCP, no shell interpolation, args array for all exec calls
4. **Graceful degradation** — Scanner failures are non-fatal; other scanners continue
5. **Comprehensive supply chain rules** — 8 detection rules covering the Axios attack pattern
6. **Good test coverage** — 55 tests across 6 test files
7. **Professional error messages** — All findings include human-readable descriptions and fix suggestions
8. **Legal references** — Each mapping rule cites OAIC guidelines and APP sections

## Test Results

```
Test Files  6 passed (6)
Tests       55 passed (55)
Duration    ~5.7s
```

## Validation Scan Results (Post-Fix)

| Project | Grade | Score | Findings | Legit? |
|---------|-------|-------|----------|--------|
| Next.js SaaS | B | 84/100 | 1 (missing lockfile) | ✅ |
| Express API | B | 79/100 | 3 (2× SQLi + lockfile) | ✅ |
| React Dashboard | B | 84/100 | 1 (missing lockfile) | ✅ |

Zero false positives remaining.