# M3 Smoke Test Results — 2026-04-26

**Commit:** `47a7054` (M3.1/M3.2: add supply-chain OSV and provenance signals)
**Tests:** 254 passing, TypeScript compiles clean, lint clean

**Follow-up:** Smoke-test issues were fixed after this run by tightening registry metadata lookup and typosquat heuristics. The scanner now prefers exact version metadata (`/<version>`) when a lockfile or exact manifest version is available, falling back to `/latest` only when no exact version is known. Scoped packages, very short names, and known legitimate ecosystem packages are no longer compared against the unscoped top-package typosquat list.

**Additional local pass:** A second local-only supply-chain smoke pass ran against 13 nearby JavaScript/TypeScript repos. That pass found three more accuracy issues and all were fixed before finalizing this note: `tsup` was still a typosquat false positive, pnpm projects were incorrectly reported as missing lockfiles, and multiline named imports such as `import { ... } from 'recharts'` were missed by unused-dependency detection.

## Test Matrix

| Repo | Findings | Critical | High | Medium | Low | OSV CVEs | Scan Time |
|---|---|---|---|---|---|---|---|
| Juice Shop (intentionally vulnerable) | 34 | 12 | 15 | 8 | 0 | 4 | 2.2s |
| Express (web framework) | 3 | 3 | 0 | 0 | 0 | 0 | 3.9s |
| SvelteKit (framework) | 2 | 2 | 0 | 0 | 0 | 0 | 1.1s |
| Next.js (28k files monorepo) | 40 | 17 | 10 | 9 | 4 | 9 | 10.6s |
| Axios (HTTP client) | 5 | 4 | 1 | 0 | 0 | 0 | 1.0s |
| Remix (full-stack framework) | 7 | 3 | 4 | 0 | 0 | 0 | 1.6s |
| Create React App (scaffold) | 2 | 1 | 1 | 0 | 0 | 0 | 0.8s |
| Turborepo (monorepo tool) | 4 | 3 | 1 | 0 | 0 | 0 | 0.9s |

## OSV.dev Findings — All Verified ✅

### Juice Shop (4 CVEs)

| OSV ID | Package | Summary | Severity | Verified |
|---|---|---|---|---|
| GHSA-c7hr-j4mj-j2w6 | jsonwebtoken | Verification Bypass in jsonwebtoken | CRITICAL | ✅ Real |
| GHSA-6g6m-m6h5-w9gf | express-jwt | Authorization bypass in express-jwt | HIGH | ✅ Real |
| GHSA-cgfm-xwp7-2cvr | sanitize-html | Sanitize-html Vulnerable To ReDoS Attacks | HIGH | ✅ Real |
| GHSA-8cf7-32gw-wr33 | jsonwebtoken | jsonwebtoken unrestricted key type could lead to legacy keys usage | HIGH | ✅ Real |

### Next.js (9 CVEs)

| OSV ID | Package | Summary | Severity | Verified |
|---|---|---|---|---|
| GHSA-3xgq-45jj-v275 | cross-spawn | Regular Expression Denial of Service (ReDoS) in cross-spawn | HIGH | ✅ Real |
| GHSA-r5fr-rjxr-66jc | lodash | lodash vulnerable to Code Injection via `_.template` imports key names | HIGH | ✅ Real |
| GHSA-23c5-xmqv-rm74 | minimatch | minimatch ReDoS: nested *() extglobs generate catastrophically backtracking regexps | HIGH | ✅ Real |
| GHSA-3ppc-4f35-3m26 | minimatch | minimatch has a ReDoS via repeated wildcards with non-matching literal in pattern | HIGH | ✅ Real |
| GHSA-7r86-cg39-jmmj | minimatch | minimatch has ReDoS: matchOne() combinatorial backtracking via multiple non-adjacent GLOBSTAR segments | HIGH | ✅ Real |
| GHSA-f8q6-p94x-37v3 | minimatch | minimatch ReDoS vulnerability | HIGH | ✅ Real |
| GHSA-pwfr-8pq7-x9qv | octokit | Unauthenticated Denial of Service in the octokit/webhooks library | HIGH | ✅ Real |
| GHSA-c2qf-rxjj-qqgw | semver | semver vulnerable to Regular Expression Denial of Service | HIGH | ✅ Real |
| GHSA-3h5v-q93c-6h6q | ws | ws affected by a DoS when handling a request with many HTTP headers | HIGH | ✅ Real |

**All 13 OSV findings are real, correctly attributed CVEs. No false positives from OSV.dev.**

## APP Mapping Accuracy

| Finding Source | APP_11 | APP_6 | APP_8 | NDB | Notes |
|---|---|---|---|---|---|
| OSV (all CVEs) | ✅ | — | — | — | All vulns map to APP_11 (security) |
| OSV (SSRF/exfiltration class) | ✅ | — | ✅ | — | Correct: cross-border disclosure risk |
| VS-SC-001 (install scripts) | ✅ | ✅ | — | — | Correct |
| VS-SC-002 (unused deps) | ✅ | ✅ | — | — | Correct |
| VS-SC-004 (typosquat) | ✅ | ✅ | — | — | Correct mapping, but many FPs (see below) |
| VS-SC-005 (missing lockfile) | ✅ | — | — | — | Correct |

**MAP-032** (OSV → APP_11), **MAP-034** (VS-SC-009 → APP_6), **MAP-035** (OSV SSRF → APP_8) all working correctly.

## VS-SC-009 (No Source Repository) — Correct Behavior ✅

- Does not fire false positives — only triggers when a real package on npm lacks `repository`/`homepage` fields
- NPM 404 (package doesn't exist) produces a recoverable `NPM_METADATA_ERROR`, not a false finding
- **Follow-up fixed:** npm metadata lookup no longer fetches the full package document for registry fallback. It uses exact version metadata when available and `/latest` as the lightweight fallback.

## VS-SC-004 (Typosquat) — False Positive Problem ⚠️

### False Positives Found (15 across 8 repos)

| Package | Matched Against | Distance | Why It's Wrong |
|---|---|---|---|
| `chai` | `chalk` | 2 | chai is a major test framework (40M+ weekly downloads) |
| `cypress` | `express` | 2 | cypress is a major e2e framework |
| `qs` | `ws` | 1 | qs is the #1 query string parser |
| `hbs` | `ws` | 1 | hbs is express-handlebars |
| `ky` | `ws` | 2 | ky is a major HTTP client |
| `swr` | `ws` | 1 | SWR is Vercel's data fetching library |
| `tsx` | `ws` | 2 | tsx is the #1 TypeScript executor |
| `vitest` | `vite` | 1 | vitest IS the vite test runner (same ecosystem) |
| `gulp` | `yup` | 2 | gulp is a major build tool |
| `alex` | `knex` | 2 | alex is a popular accessibility linter |
| `@eslint/js` | `jest` | 2 | Scoped package, different org |
| `@eslint/eslintrc` | `eslint` | 2 | Same org, definitely not typosquat |
| `@vercel/og` | `zod` | 2 | Different org, different purpose |
| `@vercel/kv` | `ajv` | 2 | Different org, different purpose |
| `@actions/core` | `cors` | 2 | GitHub Actions, not npm typosquat |
| `@changesets/cli` | `joi` | 2 | Different org, different purpose |
| `@commitlint/cli` | `joi` | 2 | Different org, different purpose |
| `@taplo/cli` | `joi` | 2 | Different org, different purpose |
| `@swc/core` | `cors` | 2 | Same org as @swc/cli |
| `@ast-grep/cli` | `joi` | 2 | Different org, different purpose |
| `@rspack/core` | `cors` | 2 | Different org |
| `oxlint` | `eslint` | 2 | Different tool, not a typosquat |

### Root Causes

1. **Short names:** Levenshtein distance ≤ 2 on 2-3 character names produces too many matches. `qs` matches `ws`, `ky` matches `ws`, etc.
2. **Scoped packages:** `@org/pkg` should not be compared against the top-100 unscoped names. The org prefix makes typosquatting via name confusion unlikely.
3. **Same-org packages:** `@eslint/eslintrc` → `eslint` are from the same org, not typosquats.
4. **Ecosystem packages:** `vitest` → `vite` are from the same ecosystem (vitest is vite's test runner).

### True Positives Found: 0

Real typosquatting is extremely rare in popular repositories. The rule is over-sensitive.

## Action Items From Smoke Test

### P0: Fix npm metadata endpoint for large packages ✅ Fixed

**File:** `src/scanner/supply-chain.ts` (line ~650)

**Problem:** The npm registry lookup uses `https://registry.npmjs.org/${packageName}` which returns the full package document. For popular packages like `typescript`, this is 15MB and exceeds the 1MB response limit, producing `NPM_METADATA_ERROR`.

**Fix landed:** Use `https://registry.npmjs.org/${packageName}/${version}` when an exact dependency version is known, with `https://registry.npmjs.org/${packageName}/latest` as the lightweight fallback. This keeps the response small and preserves version-specific provenance when a lockfile is present.

```typescript
// Current (breaks for large packages):
`https://registry.npmjs.org/${encodeURIComponent(depName)}`

// Fixed (uses version-specific metadata when available):
`https://registry.npmjs.org/${encodeURIComponent(depName)}/${encodeURIComponent(version)}`

// Fallback when no exact version is known:
`https://registry.npmjs.org/${encodeURIComponent(depName)}/latest`
```

Follow-up smoke verified `typescript@5.8.3` uses `https://registry.npmjs.org/typescript/5.8.3` and emits no `NPM_METADATA_ERROR`.

### P0: Fix typosquat false positives ✅ Fixed

**File:** `src/scanner/supply-chain.ts`

**Three changes landed:**

1. **Skip scoped packages entirely.** Packages with `@org/` prefix should not be compared against the top-100 unscoped names. Typosquatting via org scopes is a different attack vector (namespace confusion) and should be a separate, lower-severity rule.

```typescript
// In typosquat detection loop:
if (depName.startsWith('@')) return null; // Skip scoped packages
```

2. **Increase minimum name length to 4 characters.** Short names (2-3 chars) produce too many Levenshtein distance ≤ 2 matches. Real typosquats almost always use longer names (e.g., `lodash-es` vs `lodash`, `express-mock` vs `express`).

```typescript
// In typosquat detection:
if (depName.length < 4) return null; // Skip very short names
```

3. **Expand the allowlist.** Add known legitimate packages that commonly trigger false positives:

```typescript
// Add to TYPOSQUAT_ALLOWLIST:
'tsx',      // TypeScript executor (vs ws)
'vitest',   // Vite test runner (vs vite)
'gulp',     // Build tool (vs yup)
'chai',     // Test framework (vs chalk)
'cypress',  // E2E framework (vs express)
'qs',       // Query string parser (vs ws)
'ky',       // HTTP client (vs ws)
'swr',      // Vercel data fetching (vs ws)
'hbs',      // Express handlebars (vs ws)
'alex',     // Accessibility linter (vs knex)
'oxlint',   // Linter (vs eslint)
```

Follow-up local-only supply-chain smoke scans across `attestlens`, `bgm-cafe`, `strands`, `paperclip`, and `multica` produced zero `VS-SC-004` findings after these structural fixes.

### P0: Fix residual local smoke false positives ✅ Fixed

**Repos rechecked:** `MiroFish`, `argue`, `career-ops`, `cursor-talk-to-figma-mcp`, `google-indexing-script`, `lifekline`, `multica`, `opencli`, `paperclip`, `tradingview-mcp`, `attestlens`, `bgm-cafe`, and `strands`.

**Fixes landed:**

- Added `tsup` to the typosquat allowlist after it reproduced as `tsup` → `yup` in two repos.
- Treat `pnpm-lock.yaml`, `yarn.lock`, `npm-shrinkwrap.json`, `bun.lock`, and `bun.lockb` as deterministic lockfile evidence for `VS-SC-005`.
- Updated import detection to handle multiline named imports so valid imports such as `recharts` are not flagged as unused production dependencies.

**Rerun result:** zero `VS-SC-004` findings, zero pnpm-lock `VS-SC-005` false positives, and zero `VS-SC-002` findings across the 13-repo local-only pass. Remaining findings were factual install-script/missing-lockfile signals, but install-script severity still needs product tuning in M3.3/M3.5 because legitimate packages such as `esbuild` use install scripts.

### P1: Dynamic confidence for typosquat (M3.3)

Already planned in M3.3 spec. When implemented, this will:
- Lower typosquat confidence for distance-2 matches (0.7 vs 0.8 for distance-1)
- Lower confidence further for very short names
- This reduces severity from `critical` to `high` or `medium` for distance-2 FPs
- But won't eliminate FPs entirely — the above structural fixes are still needed

## Summary

| Feature | Status | Accuracy |
|---|---|---|
| OSV.dev integration | ✅ Working | 13/13 real CVEs, 0 false positives |
| APP/NDB mapping | ✅ Working | All mappings verified correct |
| VS-SC-009 (no-source-repo) | ✅ Working | No false positives, correct behavior |
| npm registry metadata | ✅ Fixed | Uses exact version endpoint or lightweight `/latest` fallback |
| VS-SC-004 (typosquat) | ✅ Improved | Scoped/short/known ecosystem false positives removed; broader validation should continue |
| Install scripts (VS-SC-001) | ✅ Working | Correctly detected `postinstall` and `prepare` |
| Unused deps (VS-SC-002) | ✅ Working | Correctly flagged unused production deps |
| Missing lockfile (VS-SC-005) | ✅ Working | Correctly detected |
| CLI `--external-enrichment` flag | ✅ Working | OSV + registry only run when opted in |
| MCP tool `externalEnrichment` param | ✅ Working | Wired through to orchestrator |
| Error recovery | ✅ Working | GuardVibe/MCP-scan absent → graceful fallback |

**M3.1 (OSV.dev): Production ready.**
**M3.2 (No-source-repo): Production ready after exact-version registry metadata fix.**
**Typosquat: Structural FP fixes landed; continue monitoring on broader real-repo validation.**
