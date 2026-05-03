# Phase 10: Schema Decoupling (Lite)

**Status:** Ready to implement
**Date:** 2026-05-01
**Prerequisite for:** Phase 11 (Rule Authoring Pipeline)
**Blocks:** YC pitch rewrite, npm publish
**Debate consensus:** Full rewrite is invisible work. Do only the minimum needed to prove a non-AU pack can flow through the same path. (See docs/DEBATE-RESULTS.md)

## Goal

Do the minimum schema decoupling needed to prove that a non-AU jurisdiction pack
can be authored, validated, and run through the same path as AU. AU stays as the
default pack, but the architecture proves portability. No full rename — just
enough to make the Phase 11 demo credible.

## Current State (Problem)

AU is special in 35 non-test files. The `RegulationPrinciple` and `RegulationMapping`
types already exist and work for CCPA/GDPR, but everything funnels back to `APPPrinciple`
for display and reporting. The goal is NOT to rename every `APPPrinciple` to `RegulationPrinciple`
(Phase 10-lite). The goal is to prove that a jurisdiction pack can flow end-to-end
without AU-specific shortcuts.

## Target State (Lite)

AU stays as the default jurisdiction and keeps its internal types. But:

1. The `RegulationMapping` path works end-to-end without `APPMapping` bridge functions
2. A new jurisdiction pack (e.g., Singapore PDPA) can be added without touching AU schema types
3. The mapping engine, report generator, and MCP tools can render any jurisdiction
   using `RegulationPrinciple` + per-jurisdiction registries
4. The Phase 11 rule-authoring pipeline can propose rules for ANY jurisdiction
5. `APPPrinciple`/`APPMapping`/`APPInfo` become internal AU-pack details, not schema foundations

Full removal of `APPPrinciple` etc. is deferred to a future refactor (post-Phase 11, post-market-validation).

## Step-by-Step Execution (Lite)

### Step 1: Make RegulationMapping the primary mapping path

Don't remove `APPMapping` yet. Instead, ensure `RegulationMapping` works end-to-end:

- Verify all mapping engine paths produce `RegulationMapping` (they already do for CCPA/GDPR)
- Add `RegulationMapping` to AU mapping rules alongside existing `APPMapping` output
- Ensure the report generator can render findings using only `RegulationMapping`
- Verify MCP tools accept `RegulationPrinciple` for all jurisdictions

### Step 2: Add per-jurisdiction principle registries

Create `PrincipleRegistry` type and AU/CCPA/GDPR registries (values from existing `APPInfo`, `CCPAPrincipleInfo`, `GDPRPrincipleInfo`):

```typescript
export interface PrincipleRegistry {
  jurisdiction: Jurisdiction;
  principles: Record<RegulationPrinciple, {
    shortName: string;
    fullName: string;
    obligation: string;
    citation?: string;
  }>;
  order: RegulationPrinciple[];
}

export function getRegistry(jurisdiction: Jurisdiction): PrincipleRegistry;
```

This replaces `APPInfo[principle]` lookups in the report generator and MCP tools.
`APPInfo` stays as an internal AU-pack detail but nothing new should reference it.

### Step 3: Add `regulationMappings` to findings (parallel to `appMappings`)

Don't remove `appMappings` yet. Add `regulationMappings` as the new primary field.
All new code uses `regulationMappings`. `appMappings` stays for backward compat.

```typescript
// Finding schema
appMappings?: APPMapping[];           // deprecated, backward compat
regulationMappings: RegulationMapping[]; // new primary
```

### Step 4: Add `regulationPrinciple` to questions (parallel to `appPrinciple`)

Don't remove `appPrinciple` yet. Add `regulationPrinciple` field.
All new code and Phase 11 pipeline uses `regulationPrinciple`.

```typescript
// Question schema
appPrinciple?: APPPrinciple;           // deprecated, backward compat
regulationPrinciple: RegulationPrinciple; // new primary
jurisdiction: Jurisdiction;
```

### Step 5: Mapping engine — ensure RegulationMapping path works for all jurisdictions

Don't remove AU-specific functions yet. Instead:

- Verify AU mapping rules produce `RegulationMapping` alongside `APPMapping`
- Add `getObligationText(jurisdiction, principle)` that uses jurisdiction registries
- Add `getShortName(jurisdiction, principle)` that uses jurisdiction registries
- These become the primary APIs; `APPInfo` lookups become internal AU compat

### Step 6: Report generator — use jurisdiction registries for display

`report/generator.ts` and `report/smb-generator.ts` use `APPInfo[principle]` for display.
Add jurisdiction-aware rendering:

```typescript
function getPrincipleInfo(jurisdiction: Jurisdiction, principle: RegulationPrinciple): PrincipleInfo {
  return getRegistry(jurisdiction).principles[principle];
}
```

Reports continue to work for all 3 jurisdictions. `APPInfo` stays as AU-pack internal.

### Step 7: MCP server — jurisdiction-agnostic principle validation

`mcp/index.ts` validates principles against `APPInfo`. Add jurisdiction-aware validation:

```typescript
function validatePrinciple(jurisdiction: Jurisdiction, principle: string): boolean {
  return principle in getRegistry(jurisdiction).principles;
}
```

### Step 8: CLI — ensure `--jurisdiction` works for all packs

CLI already has `--jurisdiction` defaulting to `au-privacy-act`. This stays.
Just verify all CLI paths work with any jurisdiction when using `RegulationMapping`.
No removal of AU-specific types from CLI yet.

### Step 9: Monitor/diff — add RegulationPrinciple support

`monitor/types.ts` and `monitor/diff.ts` use `APPPrinciple`.
Add `RegulationPrinciple` path alongside. Don't remove `APPPrinciple` yet.

### Step 10: Questionnaire flow — jurisdiction registry for display

`questionnaire/flow.ts`, `questionnaire/prompts.ts`, `questionnaire/session.ts`
use `APPInfo` for display. Change to `getRegistry(jurisdiction)`.
No removal of `APPInfo` yet.

### Step 11: Verify scanner findings work with RegulationMapping

Scanner files produce findings with `appMappings`. After Step 3, they'll also
populate `regulationMappings`. Verify no scanner creates `APPMapping` directly
(bypassing the mapping engine). If any do, add `RegulationMapping` path.

## Test Strategy

- Run full test suite after each step
- Add new tests:
  - `RegulationMapping` round-trip: finding → mapping → report for each jurisdiction
  - Principle registry lookup: verify all 3 registries produce correct display names
  - Question flow: verify `regulationPrinciple` works for all 3 jurisdictions
  - MCP tool: verify `check` validates principles per jurisdiction
  - New jurisdiction pack: add a stub (e.g., Singapore PDPA) and verify it flows end-to-end
- Target: 502+ tests still passing, tsc clean
- **Key validation:** A new jurisdiction pack should work without touching any AU-specific schema types

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Breaking MCP tool API | Low | Medium | Adding `regulationMappings` alongside `appMappings` is backward-compatible. Deprecation in next major. |
| Scope creep into full rewrite | Medium | High | Strictly limit to "prove a new pack works end-to-end." No renaming `APPPrinciple` → `RegulationPrinciple` everywhere. |
| Delay Phase 11 | Medium | High | Timebox Phase 10-lite to 3-5 days max. The goal is portability proof, not schema elegance. |
| Report format change | Low | Low | Adding fields is backward-compatible. No field removals in Phase 10-lite. |

## Version

Bump to **0.4.0** after completion. Phase 10-lite is backward-compatible
(additive fields, no removals). Breaking changes deferred to future full refactor.

## Timeline

Estimate: 3-5 days of focused work with the test suite as safety net.
Strict timebox. If scope creeps, cut steps. The only deliverable that matters:
**a new jurisdiction pack flows end-to-end without touching AU schema types.**

## After Phase 10-lite

- Phase 11 (Rule Authoring Pipeline) uses `RegulationPrinciple` and jurisdiction registries
- A stub jurisdiction pack (e.g., Singapore PDPA) validates end-to-end portability
- YC pitch rewrite: "the deploy gate for AI privacy risk" + "repeatable legislation-to-pack engine"
- Full `APPPrinciple` removal deferred to post-market-validation refactor
- npm publish as v0.4.0