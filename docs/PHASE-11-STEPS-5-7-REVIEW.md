# Phase 11 Steps 5-7 Review

## 1. Executive summary

**Verdict: FAIL**

The Phase 11 Steps 5-7 changes materially improve the rule-authoring pipeline, but the scanner still accepts `latest.runtime.json` without requiring the matching reviewed manifest to load successfully. Because authoring stage, confidence, and determinism only exist in `latest.json`, that gap allows AI-draft filtering and confidence-based severity gating to be bypassed whenever the validated manifest is missing, corrupt, partially written, or overwritten. In a security-critical path where AI-authored rules enter production scanner runtime, that is a release blocker.

## 2. Findings table

| ID | Severity | Category | Description | File:line | Recommendation |
| --- | --- | --- | --- | --- | --- |
| PH11-REVIEW-001 | P0 | Security / Runtime trust boundary | The loader trusts `latest.runtime.json` even when `latest.json` is absent or invalid, so AI-draft exclusion and confidence gating are skipped entirely. | `src/scanner/rules/loader.ts:199-255`, `src/scanner/orchestrator.ts:598-605` | Refuse to load a validated runtime pack unless the matching validated manifest parses, matches version/jurisdiction, and covers the runtime rules needed for gating. |
| PH11-REVIEW-002 | P1 | Security / Race condition | `review-pack` publishes `latest.json` and `latest.runtime.json` with separate non-atomic writes, while the loader tolerates manifest parse failures. Concurrent `scan` can observe a torn pair and fall into the bypass above. | `src/authoring/review.ts:90-97`, `src/scanner/rules/loader.ts:191-255` | Write both files to temp names and atomically rename them into place; fail closed if either side is unreadable or inconsistent. |
| PH11-REVIEW-003 | P1 | Correctness / Output safety | `.runtime.json` path derivation is `replace(/\.json$/, '.runtime.json')`. If `--output` does not end in `.json`, the runtime write targets the same path and overwrites the validated manifest. | `src/authoring/review.ts:96-97`, `src/cli/index.ts:666-685` | Enforce `.json` output paths in the CLI or derive the sibling path with `path.parse()` and reject ambiguous names. |
| PH11-REVIEW-004 | P2 | Correctness / Version validation | `comparePackVersions()` accepts arbitrary strings and uses `Number(part)`, so malformed versions can yield `NaN` and defeat the stale-pack fallback check. | `src/scanner/rules/loader.ts:488-500` | Validate version format before comparison or store versions in a schema-constrained numeric form. |

## 3. Detailed findings

### PH11-REVIEW-001 — Runtime pack is accepted without reviewed metadata

**Code**

```ts
try {
  validatedManifest = await readValidatedPackFromFile(validatedPath);
} catch (error: any) {
  if (error.code !== 'ENOENT') {
    warnings.push(`Validated pack manifest ignored for ${jurisdiction}: ${error.message}`);
  }
}

if (!runtimeManifest) {
  return { manifest: embedded, ... };
}

const authoredRulesById = new Map<string, AuthoredRuleType>();
if (validatedManifest) {
  // populate gating metadata
}

const filteredRuntimeRules = runtimeManifest.rules.filter((rule) => {
  const authoredRule = authoredRulesById.get(rule.id);
  return true;
});
```

```ts
severity: authoredRule ? resolveEffectiveSeverity({
  ...authoredRule,
  severity: rule.severity,
}) : rule.severity,
```

**Impact**

If `latest.runtime.json` is valid but `latest.json` is missing, corrupt, truncated, or otherwise unreadable, the loader still returns the runtime pack. In that state:

- AI-draft filtering has no metadata to act on.
- `authoredRulesById` is empty.
- `mergeRulePackManifests()` keeps the runtime rule’s severity unchanged.
- `resolveEffectiveSeverity()` never runs.

This is exactly the unsafe path the phase is supposed to prevent. A runtime pack with low-confidence or AI-authored rules can enter scanner execution at full severity simply by separating it from the reviewed manifest.

This also fails the user’s requested edge cases:

- `latest.runtime.json` valid + `latest.json` corrupt: runtime rules still load.
- `latest.runtime.json` valid + `latest.json` missing: runtime rules still load.
- Different rule counts or divergent rule IDs: there is no consistency check.

**Fix**

Fail closed. Only trust `latest.runtime.json` when the matching validated manifest also parses and passes cross-checks:

- same jurisdiction
- same version
- same rule ID set, or at least a defined subset relation
- enough metadata to compute severity for every runtime rule that came from the validated pack

If the validated manifest cannot be loaded, fall back to embedded rules instead of runtime rules.

### PH11-REVIEW-002 — Non-atomic publication allows torn validated/runtime pairs

**Code**

```ts
await fs.writeFile(path.resolve(options.outputPath), `${JSON.stringify(manifest, null, 2)}\n`, 'utf-8');
const runtimeOutputPath = path.resolve(options.outputPath).replace(/\.json$/, '.runtime.json');
await fs.writeFile(runtimeOutputPath, `${JSON.stringify(runtimePack, null, 2)}\n`, 'utf-8');
```

**Impact**

`review-pack` publishes the reviewed manifest and runtime pack with two separate writes, directly to final paths. `scan` reads those files independently and accepts runtime-only state. During concurrent `review-pack` and `scan`:

- `scan` can read one new file and one old file.
- `scan` can hit a partially written `latest.json`, log a warning, and still accept `latest.runtime.json`.
- Rule counts, versions, and severity metadata can temporarily disagree with no hard failure.

That creates a real race-based path into the P0 bypass above. This is especially risky because the files live in the shared production discovery location `~/.attestlens/jurisdictions/<j>/`.

**Fix**

Publish atomically:

1. Write `latest.json.tmp` and `latest.runtime.json.tmp`.
2. `fs.rename()` each into place only after both writes succeed.
3. Include consistency checks in the loader and fail closed on mismatch.

### PH11-REVIEW-003 — Runtime output path derivation can overwrite the validated manifest

**Code**

```ts
const runtimeOutputPath = path.resolve(options.outputPath).replace(/\.json$/, '.runtime.json');
await fs.writeFile(runtimeOutputPath, ...);
```

**Impact**

The CLI only requires `--output <path>`; it does not require a `.json` suffix. If the caller passes:

- `--output /path/latest`
- `--output /path/validated`

then `.replace(/\.json$/, ...)` is a no-op and `runtimeOutputPath === outputPath`. The second write overwrites the validated manifest with the runtime pack. After that, the reviewed manifest is gone and the system is left in the unsafe runtime-only state from PH11-REVIEW-001.

This is a silent corruption bug on a security-sensitive artifact.

**Fix**

Derive sibling names with `path.parse()` and reject ambiguous inputs. For example:

- require `--output` to end in `.json`
- reject `.runtime.json` as the primary output name
- compute the runtime sibling as `${name}.runtime${ext}`

Add a test for non-`.json` output paths.

### PH11-REVIEW-004 — Version comparison is too permissive and can mis-handle malformed versions

**Code**

```ts
function comparePackVersions(left: string, right: string): number {
  const leftParts = left.split('.').map((part) => Number(part));
  const rightParts = right.split('.').map((part) => Number(part));
  ...
  const delta = (leftParts[index] || 0) - (rightParts[index] || 0);
  if (delta !== 0) {
    return delta;
  }
}
```

**Impact**

The schemas only require `version: z.string()`. A malformed version such as `2026.05.01-beta` yields `NaN` parts. `delta !== 0` is true for `NaN`, so the function returns `NaN`, and the caller’s `< 0` check does not fire. That means malformed or attacker-supplied version strings can bypass the “older than embedded” fallback.

This is not the primary security flaw, but it weakens the trust boundary further.

**Fix**

Constrain versions to a strict numeric format in schema, or parse with explicit validation and throw on any non-numeric component before comparison.

## 4. Positive observations

- `resolveEffectiveSeverity()` itself is correctly monotonic: `capSeverity()` cannot upgrade `low` to a higher severity, and the high/medium/low cases map as expected.
- The duplicate-ID checks added to `ProposedPackManifest`, `ValidatedPackManifest`, and runtime rule-pack validation are useful hardening.
- The stricter authored-rule invariants are directionally correct: `ai-draft` must require review, and `human-validated` must carry approval provenance.
- Local and remote rule-pack size checks are in place before parsing, including validated-pack reads.
- Jurisdiction path construction is reasonably safe against traversal because the jurisdiction segment comes from the enum, not raw user input.
- The demo does not print `OPENAI_API_KEY`, and the hardcoded secret in `demo/test-project/server.js` is an obvious placeholder rather than an apparent real credential.

## 5. Test coverage gaps

- No test covers `latest.runtime.json` present while `latest.json` is missing or corrupt. That is the highest-risk untested path.
- No test covers mismatched rule IDs or rule counts between `latest.json` and `latest.runtime.json`.
- No test covers concurrent `review-pack` and `scan`, partial writes, or torn reads.
- No test covers `--output` without a `.json` suffix or with an existing `.runtime.json` suffix.
- No test covers malformed version strings in `comparePackVersions()`.
- No test proves the loader fails closed when validated metadata is unavailable; current tests only cover the happy path, AI-draft filtering when metadata exists, and “older than embedded”.

## 6. Overall recommendation

Do not ship this phase as-is. The critical fix is to make the runtime pack dependent on a successfully loaded, cross-checked reviewed manifest, and to publish/read the two artifacts atomically. Once that is fixed, add the missing tests above before re-review.
