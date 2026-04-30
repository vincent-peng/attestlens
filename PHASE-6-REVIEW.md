# Phase 6 Jurisdiction Abstraction Review

Review scope: `git diff main...feature/jurisdiction-abstraction`

Branch reviewed: `feature/jurisdiction-abstraction` at `74f81d0`

Merge base: `85336a2`

## Validation

- `npx tsc --noEmit`: passed.
- `npx vitest run`: failed.
  - 20 test files passed.
  - 4 test files failed.
  - 10 tests timed out.
  - 2 suite hooks timed out.
  - Failed files observed:
    - `src/scanner/guardvibe.test.ts`
    - `src/scanner/orchestrator.test.ts`
    - `src/scanner/rules/repo-stack-checks.test.ts`
    - `src/cli/index.test.ts`
- `git diff --check main...feature/jurisdiction-abstraction`: passed.
- CLI unavailable-jurisdiction smoke check passed with a graceful error:
  - `node --import tsx src/cli/index.ts scan . --jurisdiction us-ccpa --no-guardvibe --no-mcp-scan --no-supply-chain --no-behavioral --no-iac`
  - Returned: `jurisdiction 'us-ccpa' is not yet available. Available jurisdictions: au-privacy-act`
- Direct `npx tsx ...` failed in this sandbox with `listen EPERM` on the tsx IPC pipe; rerunning through `node --import tsx` matched the test harness and reached the AttestLens code path.

## Findings

### C-01: `mapAllFindings(findings, true)` no longer enables strict mode

Severity: C

Files:
- `src/mapping/engine.ts:940`
- `src/mapping/engine.ts:1081`
- `src/mapping/engine.ts:1207`

The old exported API was:

```ts
mapAllFindings(findings, strictMode = false): { controls: APPControl[]; unmapped: AttestLensFinding[] }
```

Phase 6 changes it to:

```ts
mapAllFindings(findings, options = {}): { controls: RegulationControl[]; unmapped: AttestLensFinding[] }
```

That is a backward compatibility break for existing AU-only callers. In JavaScript, `mapAllFindings([], true)` still runs, but `options.strictMode === true` is false because `options` is the boolean primitive. Strict mode is silently ignored.

Repro run:

```bash
node --import tsx --input-type=module -e "import { mapAllFindings } from './src/mapping/engine.ts'; const result = mapAllFindings([], true); console.log(JSON.stringify({ failCount: result.controls.filter(c => c.status === 'fail').length, unknownCount: result.controls.filter(c => c.status === 'unknown').length }, null, 2));"
```

Observed:

```json
{ "failCount": 0, "unknownCount": 14 }
```

Expected for legacy strict AU usage: unknown controls become failed. The return shape also now includes `jurisdiction` on controls, so deep equality or schema checks written against `APPControl` can break unless callers discover and switch to `mapAllFindingsAU`.

Recommended fix: keep `mapAllFindings` backward-compatible via an overload/normalizer that accepts `boolean | MapAllFindingsOptions`, and either preserve the APP-shaped return for the legacy path or introduce a new `mapAllFindingsForJurisdictions` name for the regulation-shaped result. Add a regression test for `mapAllFindings([], true)`.

### C-02: Unavailable jurisdictions are rejected by CLI/MCP wrappers, but not by the exported scanner engine

Severity: C

Files:
- `src/scanner/orchestrator.ts:50`
- `src/scanner/orchestrator.ts:86`
- `src/scanner/rules/loader.ts:101`
- `src/scanner/rules/loader.ts:119`
- `src/scanner/rules/loader.ts:357`

The CLI and MCP surfaces correctly reject `us-ccpa` / `eu-gdpr` before scanning. The lower-level exported scanner surface does not. `ScannerOrchestrator` accepts `jurisdictions`, calls `loadJurisdictionPacks`, and the loader returns an empty pack plus a recoverable warning for unavailable jurisdictions.

Repro run:

```bash
node --import tsx --input-type=module -e "import { ScannerOrchestrator } from './src/scanner/orchestrator.ts'; const r = await new ScannerOrchestrator({ jurisdictions: ['us-ccpa'] }).scan('.', []); console.log(JSON.stringify({ errors: r.errors, findings: r.findings.length, ruleFreshness: r.ruleFreshness }, null, 2));"
```

Observed: the scan completed successfully with `ruleFreshness.version = "unavailable"` and a recoverable `JURISDICTION_PACK_WARNING`.

This violates the stated fail-closed behavior for unavailable jurisdictions if any caller uses the exported scanner API directly. It can also produce zero-rule successful scans, which is risky for a compliance engine because it looks like a completed assessment rather than an unsupported jurisdiction.

Recommended fix: centralize availability enforcement in `ScannerOrchestrator` or `loadJurisdictionPacks`, not only in CLI/MCP callers. If warning-only loading is needed for future pack discovery, gate it behind an explicit option such as `allowUnavailableJurisdictions`.

### Q-01: Regulation schemas lose citation and do not validate jurisdiction/principle consistency

Severity: Q

Files:
- `src/schema/index.ts:98`
- `src/schema/index.ts:110`
- `src/schema/index.ts:309`
- `src/mapping/engine.ts:38`
- `src/mapping/engine.ts:962`

`MappingRule` now has an optional `citation`, but `RegulationMapping` has no citation field and `mapFindingToRegulation` does not propagate `rule.citation`. `RegulationControl` has optional `citation`, but `mapAllFindings` does not populate it either.

The schema also treats `RegulationPrinciple` as any non-empty string, with no refinement that AU mappings use `APPPrinciple`, CCPA mappings use a CCPA ID, GDPR mappings use a GDPR ID, or rule mappings match the surrounding jurisdiction pack. That is acceptable for early scaffolding, but it is weak for a foundational compliance abstraction because invalid legal references will parse successfully and may only fail later through silent omission from APP compatibility wrappers.

Recommended fix: include citation in `RegulationMapping` or a dedicated legal-reference object, populate citations from mapping rules and jurisdiction packs, and add schema-level or loader-level checks that a rule pack's mappings match its declared jurisdiction. At minimum, refine AU mappings to require valid `APPPrinciple`.

### T-01: Missing regression coverage for the compatibility and rejection boundaries

Severity: T

Files:
- `src/mapping/engine.test.ts:432`
- `src/mcp/index.test.ts:366`
- `src/cli/index.test.ts:392`
- `src/scanner/rules/loader.test.ts:232`

The new tests cover many happy paths, but they miss the behaviors most likely to regress:

- Legacy `mapAllFindings(findings, true)` strict-mode behavior.
- Legacy APP-shaped `mapAllFindings` return shape, if that function remains public.
- Direct `ScannerOrchestrator({ jurisdictions: ['us-ccpa'] })` rejection.
- `updateRuleCache` / `loadRulePack` rejection or quarantine for cached rule packs declaring unavailable jurisdictions.
- Unavailable-jurisdiction rejection on every exposed CLI/MCP surface, not just CLI `scan` and MCP `attestlens_check`.
- Schema rejection of mismatched mappings, such as an AU pack containing `jurisdiction: "eu-gdpr"` or an AU principle that is not an `APPPrinciple`.

Recommended fix: add narrow tests for these boundary cases. C-01 would have been caught by a single legacy strict-mode test.

## Security Notes

No S-class injection, unauthorized access, or sensitive data leakage issue was found in the jurisdiction parameter handling reviewed here. The new CLI/MCP jurisdiction arguments are parsed through Zod enums or CLI helper validation, and the MCP path/root validation remains in place before scans.

One security-relevant correctness risk remains: C-02 should fail closed at the exported scanner boundary so unsupported jurisdictions cannot produce successful-looking no-rule scans.

## Mapping Logic Check

I did not find a change to the existing AU mapping rule predicates, statuses, confidences, or rationales. A zero-context diff over `src/mapping/engine.ts` showed the rule-body changes are structural renames (`appPrinciple` to `regulationPrinciple`, `oaicReference` to `citation`) plus new wrapper code, not changes to the existing AU rule matching logic.

## Backward Compatibility Summary

Internal report/questionnaire callers were migrated to `mapAllFindingsAU`, and default CLI/MCP AU behavior appears preserved. The exported `mapAllFindings` function is the compatibility problem: existing AU-only consumers can silently lose strict mode and receive a different control shape.

## Recommendation

Do not merge Phase 6 until C-01 is fixed. C-02 should also be fixed before treating unavailable jurisdiction rejection as complete. Q-01 can be fixed in this phase or explicitly documented as Phase 7 schema hardening, but it should not remain implicit.
