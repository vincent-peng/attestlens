# Phase 11 Steps 1-4 Code Review

## 1. Executive Summary

**Verdict: FAIL**

The Phase 11 authoring pipeline is moving in the right direction, but it is not safe to treat as a completed security-critical lifecycle yet. The strongest parts are the runtime separation of LLM code from scanners and the normalization that forces `ai-draft` plus `reviewRequired: true` during proposal generation. The main blockers are:

- `review-pack --approve-all` can mint `human-validated` packs with no real per-rule review.
- The reviewed output format (`ValidatedPackManifest` schema `2.1`) is not consumable by the current rule-pack loader/runtime, which still only accepts `RulePackManifest` schema `1.0`.
- Proposed/validated manifests do not enforce unique authored rule IDs.
- Schema invariants for approved rules are too weak, and the new schemas are not strict, which leaves room for invalid or drifting states.

I also found smaller resilience issues around unbounded legislation input and unchecked regex complexity during harness execution.

## 2. Findings Table

| ID | Severity | Category | Description | File:Line | Recommendation |
| --- | --- | --- | --- | --- | --- |
| PH11-001 | P1 | security | `review-pack --approve-all` bypasses the promised human approval gate and still stamps rules as `human-validated`. | `src/cli/index.ts:669`, `src/authoring/review.ts:47`, `src/authoring/review.ts:123` | Remove the flag from production CLI, or hard-gate it behind a test/dev env check and emit unmistakable non-production provenance. |
| PH11-002 | P1 | correctness | The validated output cannot be loaded by the current runtime loader; scanner ingestion still parses only schema `1.0` rule packs. | `src/authoring/review.ts:67`, `src/schema/index.ts:655`, `src/scanner/rules/loader.ts:301`, `src/scanner/rules/loader.ts:315` | Either emit a runtime-consumable manifest alongside `2.1`, or teach loaders/scanners how to read validated authored packs safely. |
| PH11-003 | P1 | correctness | Duplicate authored rule IDs are not rejected in proposed/validated manifests, so harness/provenance maps can silently overwrite earlier entries. | `src/authoring/propose.ts:183`, `src/authoring/review.ts:34`, `src/authoring/review.ts:64`, `src/schema/index.ts:633`, `src/schema/index.ts:655` | Add duplicate-ID validation to `ProposedPackManifest` and `ValidatedPackManifest`, and fail review on collisions. |
| PH11-004 | P1 | architecture | Schema invariants for approved rules are incomplete, and the new authored schemas are non-strict, allowing invalid approved states and silent schema drift. | `src/schema/index.ts:547`, `src/schema/index.ts:558`, `src/schema/index.ts:574`, `src/schema/index.ts:595`, `src/schema/index.ts:655` | Make the new objects `.strict()` and add refinements for `human-validated` rules requiring approval provenance and `reviewRequired: false`. |
| PH11-005 | P2 | edge-case | `proposeRules()` reads the entire legislation file and injects it into both prompts with no byte/token cap, which risks cost blowups, memory pressure, and degraded LLM behavior on hostile or very large input. | `src/authoring/propose.ts:54`, `src/authoring/propose.ts:71`, `src/authoring/propose.ts:80`, `src/authoring/prompt.ts:23`, `src/authoring/prompt.ts:43` | Add file-size and prompt-budget limits, truncate or chunk long inputs, and fail early with a clear operator-facing error. |
| PH11-006 | P2 | security | Custom regex patterns are compiled directly in the harness with no complexity checks, so a crafted rule can hang review with catastrophic backtracking. | `src/authoring/test-harness.ts:95`, `src/scanner/rules/executable.ts:117` | Add regex validation/allowlisting, complexity linting, and per-test execution timeouts before enabling custom rules in the harness. |

## 3. Detailed Findings

### PH11-001: `--approve-all` breaks the human-review guarantee

**Snippet**

```ts
.option('--approve-all', 'Approve all proposed rules without prompting (testing only)')

if (options.approveAll) {
  decision = 'approve';
}

authoring: {
  ...rule.authoring,
  author: 'human-validated',
},
```

**Where**

- `src/cli/index.ts:669`
- `src/authoring/review.ts:47`
- `src/authoring/review.ts:123`

**Impact**

This is the clearest violation of the new lifecycle’s control objective. A caller can run `review-pack --approve-all --reviewer anything` and produce a manifest whose rules are marked `human-validated` without any rule-by-rule human decision. That undermines the claimed enforcement boundary between AI drafting and human approval.

Because the flag is exposed in the normal CLI and not test-only in code, this is not just a unit-test escape hatch. It is a production bypass.

**Fix**

- Remove `--approve-all` from the production command surface.
- If it must exist for fixtures/tests, gate it behind an explicit env var such as `ATTESTLENS_UNSAFE_TEST_MODE=1`.
- If unsafe auto-approval is ever allowed, stamp a separate non-runnable author stage or manifest type so it cannot be mistaken for a reviewed pack.

### PH11-002: reviewed packs are not consumable by the runtime loader

**Snippet**

```ts
const manifest = ValidatedPackManifest.parse({
  schemaVersion: '2.1',
  ...
});
```

```ts
function parseRulePackJson(raw: string, sourceLabel: string): RulePackManifestType {
  try {
    return validateRulePackManifest(JSON.parse(raw));
  } catch (error: any) {
    throw new Error(`Invalid rule pack manifest from ${sourceLabel}: ${error.message}`);
  }
}

function validateRulePackManifest(raw: unknown): RulePackManifestType {
  const manifest = RulePackManifest.parse(raw);
```

**Where**

- `src/authoring/review.ts:67`
- `src/schema/index.ts:655`
- `src/scanner/rules/loader.ts:301`
- `src/scanner/rules/loader.ts:315`

**Impact**

`reviewPack()` emits schema `2.1` with authored-rule metadata, but the current runtime loader still accepts only `RulePackManifest` schema `1.0`. That means the output of the new review flow cannot be fed back into the existing pack-loading path used by scans and audits.

For a security-critical feature, this is a lifecycle break: the code can draft and approve rules, but it cannot operationalize them through the normal runtime path.

**Fix**

- Decide on the canonical runtime artifact.
- Either:
  - emit a companion schema `1.0` executable pack from `reviewPack()`, or
  - extend loader/runtime support to accept validated authored packs and down-convert only the executable subset.
- Add an integration test that round-trips `reviewPack()` output through the loader and a scanner.

### PH11-003: duplicate authored rule IDs are silently accepted

**Snippet**

```ts
return rawRules.map((rule) => {
  ...
  return AuthoredRuleSchema.parse({
    ...rawRule,
```

```ts
const harnessByRuleId = new Map(harnessResults.map((result) => [result.ruleId, result]));
...
ruleProvenance[approvedRule.id] = approvedRule.provenance;
```

**Where**

- `src/authoring/propose.ts:183`
- `src/authoring/review.ts:34`
- `src/authoring/review.ts:64`
- `src/schema/index.ts:633`
- `src/schema/index.ts:655`

**Impact**

The prompt asks the model for unique IDs, but the code never enforces uniqueness in proposed or validated manifests. If the LLM emits duplicate IDs:

- the harness result map keeps only the last result for that ID,
- `ruleProvenance` overwrites earlier provenance entries,
- downstream scanner behavior becomes ambiguous because `sourceRule` is no longer a unique key.

This is an integrity bug, not just a cosmetic one.

**Fix**

- Add a `superRefine` on `ProposedPackManifest` and `ValidatedPackManifest` to reject duplicate `rules[].id`.
- Reject duplicates before writing output files.
- Add tests covering duplicate IDs from the LLM and duplicate IDs introduced during edit/review.

### PH11-004: authored-rule schemas are too permissive

**Snippet**

```ts
export const RuleProvenance = z.object({
  draftedByModel: z.string().optional(),
  ...
  approvedBy: z.string().optional(),
  approvedAt: z.string().datetime().optional(),
  packVersion: z.string().optional(),
});

export const AuthoredRule = AuthoredRuleBase.superRefine((rule, ctx) => {
  if (rule.authoring.author === 'ai-draft' && rule.interpretation.reviewRequired !== true) {
    ...
  }
});
```

**Where**

- `src/schema/index.ts:547`
- `src/schema/index.ts:558`
- `src/schema/index.ts:574`
- `src/schema/index.ts:595`
- `src/schema/index.ts:655`

**Impact**

The new schemas enforce only one direction of the state machine: `ai-draft` must have `reviewRequired: true`. They do not enforce the inverse approved-state invariants:

- `human-validated` can still omit `approvedBy`, `approvedAt`, and `packVersion`.
- `human-validated` can still carry `reviewRequired: true`.
- `ValidatedPackManifest` can contain approved rules that are structurally incomplete.

Also, the new Zod objects use plain `z.object(...)` rather than `.strict()`. In Zod v3 that silently strips unknown fields instead of rejecting them. For an LLM-facing schema, silent stripping is a bad default because it hides schema drift and unexpected output.

**Fix**

- Make `RuleProvenance`, `RuleInterpretation`, `AuthoredRule`, `ProposedPackManifest`, and `ValidatedPackManifest` strict.
- Add invariants such as:
  - `author === 'human-validated'` requires `approvedBy`, `approvedAt`, `packVersion`, and `reviewRequired === false`.
  - `author === 'community'` must have a separately defined provenance contract.
- Consider a discriminated union by `authoring.author` instead of a single loose authored-rule schema.

### PH11-005: proposal input is unbounded and duplicated into prompts

**Snippet**

```ts
const legislationText = await fs.readFile(path.resolve(options.sourcePath), 'utf-8');
...
prompt: buildObligationExtractionPrompt(promptContext),
...
prompt: buildRuleGenerationPrompt(promptContext, JSON.stringify(obligations, null, 2)),
```

```ts
'Legislation text follows:',
context.legislationText,
```

**Where**

- `src/authoring/propose.ts:54`
- `src/authoring/propose.ts:71`
- `src/authoring/propose.ts:80`
- `src/authoring/prompt.ts:23`
- `src/authoring/prompt.ts:43`

**Impact**

The authoring path reads the whole source file into memory and injects the full text into both LLM passes. There is no byte limit, token budgeting, truncation, or chunking. A very large or intentionally hostile input can:

- cause high-cost API calls,
- exceed model context limits,
- increase parse failures,
- increase memory pressure locally.

This is partly a resilience issue and partly a cost/availability risk.

**Fix**

- Apply an explicit max input size before reading or before prompting.
- Estimate prompt tokens and either chunk the legislation or fail fast.
- Delimit the legislation clearly and add instructions that source text is data, not instructions.

### PH11-006: harness compiles untrusted regexes directly

**Snippet**

```ts
const result = await adapter.scan(tempDir, {
  rulePack: buildSingleRulePack(rule),
  allowCustomRules: true,
});
```

```ts
regex: new RegExp(definition.pattern, definition.flags),
```

**Where**

- `src/authoring/test-harness.ts:95`
- `src/scanner/rules/executable.ts:117`

**Impact**

This does preserve the “AI only at authoring time” runtime boundary, but it still means the review path executes model-supplied regexes inside the harness. Invalid regexes are caught indirectly, but pathological regexes can still consume CPU during test execution and make review non-responsive.

The risk surface is limited to authoring/review, not production scan runtime, which is why this is P2 rather than P1.

**Fix**

- Validate regex syntax and complexity before scanning.
- Add a per-test timeout around harness execution.
- Consider banning constructs known for catastrophic backtracking in authored rules unless explicitly overridden by a human.

## 4. Positive Observations

- The authoring code is cleanly separated from runtime scanning. There are no LLM imports in the scanner modules I reviewed.
- `proposeRules()` force-normalizes critical lifecycle fields instead of trusting the model:
  - `authoring.author` is set to `ai-draft`.
  - `interpretation.reviewRequired` is set to `true`.
  - provenance is stamped with the prompt version and source document hash.
- The scanner-side `allowCustomRules` switch is scoped narrowly. In this change set it is only enabled by the test harness, which is aligned with the “AI only at authoring time, never at runtime” goal.
- API keys are not logged, echoed into output manifests, or embedded in error messages.
- No new third-party dependency appears to have been introduced for Phase 11. `@inquirer/prompts` was already present.
- The targeted Phase 11 tests that exist do pass when run outside the sandbox.

## 5. Test Coverage Gaps

- No test rejects duplicate authored rule IDs in `ProposedPackManifest` or `ValidatedPackManifest`.
- No integration test proves that `reviewPack()` output can be loaded by the scanner runtime. Today it cannot.
- No test covers `review-pack` with zero rules.
- No test covers malformed second-pass JSON or malformed first-pass JSON beyond the generic parse error path.
- No test covers empty legislation input.
- No test covers very large legislation input or prompt-budget enforcement.
- No test covers invalid regex syntax or catastrophic regex behavior in the harness.
- No test covers authored rules with no `pattern` but with positive/negative cases.
- No test asserts that production review cannot be bypassed with `--approve-all`.

## Verification

Targeted tests run successfully outside the sandbox:

```text
npm test -- --run src/authoring/propose.test.ts src/authoring/review.test.ts src/authoring/test-harness.test.ts src/schema/index.test.ts src/cli/index.test.ts
67 passed / 67 total
```
