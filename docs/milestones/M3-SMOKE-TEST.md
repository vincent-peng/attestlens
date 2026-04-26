# M3 Smoke Test Results — 2026-04-26

**Commit:** `47a7054` (M3.1/M3.2: add supply-chain OSV and provenance signals)
**Tests:** 254 passing, TypeScript compiles clean, lint clean

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
- **Bug found:** npm metadata lookup fails for packages >1MB (e.g., `typescript` at 15MB). Should use `/latest` endpoint instead of full package document. See action items below.

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

## Action Items for Next Codex Pass

### P0: Fix npm metadata endpoint for large packages

**File:** `src/scanner/supply-chain.ts` (line ~650)

**Problem:** The npm registry lookup uses `https://registry.npmjs.org/${packageName}` which returns the full package document. For popular packages like `typescript`, this is 15MB and exceeds the 1MB response limit, producing `NPM_METADATA_ERROR`.

**Fix:** Use the abbreviated endpoint `https://registry.npmjs.org/${packageName}/latest` which returns only the latest version metadata (~4KB for `typescript`). This contains `repository` and `homepage` fields needed for VS-SC-009.

```typescript
// Current (breaks for large packages):
`https://registry.npmjs.org/${encodeURIComponent(depName)}`

// Fixed (uses /latest for smaller response):
`https://registry.npmjs.org/${encodeURIComponent(depName)}/latest`
```

This is a one-line change that eliminates the `NPM_METADATA_ERROR` for popular packages in the Remix scan output.

### P0: Fix typosquat false positives

**File:** `src/scanner/supply-chain.ts`

**Three changes needed:**

1. **Skip scoped packages entirely.** Packages with `@org/` prefix should not be compared against the top-100 unscoped names. Typosquatting via org scopes is a different attack vector (namespace confusion) and should be a separate, lower-severity rule.

```typescript
// In typosquat detection loop:
if (depName.startsWith('@')) continue; // Skip scoped packages
```

2. **Increase minimum name length to 4 characters.** Short names (2-3 chars) produce too many Levenshtein distance ≤ 2 matches. Real typosquats almost always use longer names (e.g., `lodash-es` vs `lodash`, `express-mock` vs `express`).

```typescript
// In typosquat detection:
if (depName.length < 4) continue; // Skip very short names
```

3. **Expand the allowlist.** Add known legitimate packages that commonly trigger false positives:

```typescript
// Add to TYPOSQUAT_ALLOWLIST:
'TSX',      // TypeScript executor (vs ws)
'VITEST',   // Vite test runner (vs vite)
'GULP',     // Build tool (vs yup)
'CHAI',     // Test framework (vs chalk)
'CYPRESS',  // E2E framework (vs express)
'QS',       // Query string parser (vs ws)
'KY',       // HTTP client (vs ws)
'SWR',      // Vercel data fetching (vs ws)
'HBS',      // Express handlebars (vs ws)
'ALEX',     // Accessibility linter (vs knex)
'OXLINT',   // Linter (vs eslint)
```

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
| npm registry metadata | ⚠️ Bug | Fails for packages >1MB, needs `/latest` endpoint |
| VS-SC-004 (typosquat) | ⚠️ High FP rate | 15 FPs across 8 repos, 0 true positives |
| Install scripts (VS-SC-001) | ✅ Working | Correctly detected `postinstall` and `prepare` |
| Unused deps (VS-SC-002) | ✅ Working | Correctly flagged unused production deps |
| Missing lockfile (VS-SC-005) | ✅ Working | Correctly detected |
| CLI `--external-enrichment` flag | ✅ Working | OSV + registry only run when opted in |
| MCP tool `externalEnrichment` param | ✅ Working | Wired through to orchestrator |
| Error recovery | ✅ Working | GuardVibe/MCP-scan absent → graceful fallback |

**M3.1 (OSV.dev): Production ready.**
**M3.2 (No-source-repo): Production ready, pending npm `/latest` endpoint fix.**
**Typosquat: Needs structural FP fixes before considering production-ready.**