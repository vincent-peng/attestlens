# Rule Authoring Pipeline — AI-Suggested Rules

**Status:** Design proposal
**Date:** 2026-05-01

## Problem

Clearway has 68 scanner rules across 3 jurisdictions, all hand-written in TypeScript.
Every rule traces to specific legislative text, but the creation process is:

```
Legislation → human reads → human writes regex/rule → hardcoded in src/
```

This doesn't scale to 137 jurisdictions. More importantly, it doesn't give YC
the AI story they want: Clearway doesn't *use* AI, it just *checks* things.

## Proposal: AI-Assisted Rule Authoring

Add a pipeline where AI ingests legislation and proposes rules that a human validates
before they enter the jurisdiction pack. The scanner stays deterministic (zero LLM calls
at runtime). But rule creation becomes 10-100x faster.

```
Legislation PDF/text
  → AI extracts obligations (principles, controls, citations)
  → AI proposes scanner rules (patterns, severities, mappings)
  → AI proposes questionnaire questions (with applicability gates)
  → Human reviews, edits, approves
  → Approved rules enter the jurisdiction pack
  → Deterministic scanner runs the validated pack at runtime
```

## Architecture

### New Components

#### 1. `RuleAuthor` — AI-assisted rule creation service

```typescript
interface RuleAuthorInput {
  jurisdiction: Jurisdiction;
  legislationText: string;       // Raw legislation text
  legislationUrl?: string;        // Source URL for citation
  existingRules?: RulePackManifest; // Current pack to diff against
}

interface RuleAuthorOutput {
  jurisdiction: Jurisdiction;
  principles: ProposedPrinciple[];
  scannerRules: ProposedRule[];
  mappingRules: ProposedMapping[];
  questionnaireQuestions: ProposedQuestion[];
  reformProvisions?: ProposedReform[];
  confidence: 'high' | 'medium' | 'low';
  citations: Citation[];
  warnings: string[];
  gaps: string[];  // Areas where legislation is ambiguous
}
```

This is the **only** part of Clearway that calls an LLM. It runs offline, during
rule pack creation, not during scanning.

#### 2. `PackReviewer` — Human validation interface

```typescript
interface PackReview {
  id: string;
  proposed: RuleAuthorOutput;
  reviews: ReviewDecision[];  // approve, reject, edit per rule
  finalPack: JurisdictionPackManifest;
  reviewer: string;
  reviewedAt: Date;
}
```

CLI command:
```bash
attestlens review-pack --jurisdiction eu-gdpr --proposed ./proposed-gdpr-pack.json
```

Interactive review: shows each proposed rule, AI confidence, citation, and lets
the reviewer approve/reject/edit before it enters the pack.

#### 3. `PackCompiler` — Compile reviewed proposals into executable packs

Takes a reviewed `PackReview` and compiles it into the same `JurisdictionPackManifest`
format that the scanner loads today. No change to the runtime.

### Data Flow

```
                    ┌─────────────────────────────────────┐
                    │         Rule Creation Phase          │
                    │         (offline, AI-assisted)       │
                    │                                     │
  Legislation ────►│  RuleAuthor (LLM)                   │
  (PDF/text)        │    ↓                                │
                    │  Proposed Pack                      │
                    │    ↓                                │
                    │  PackReviewer (human)               │
                    │    ↓                                │
                    │  Approved Pack ──► PackCompiler      │
                    │    ↓                                │
                    │  JurisdictionPackManifest            │
                    └──────────┬──────────────────────────┘
                               │
                    ┌──────────▼──────────────────────────┐
                    │         Runtime Phase                  │
                    │         (online, deterministic)       │
                    │                                     │
                    │  Scanner loads pack                   │
                    │    ↓                                 │
                    │  Deterministic rules execute          │
                    │    ↓                                 │
                    │  Findings → Mapping → Opinion         │
                    │    ↓                                 │
                    │  Signed compliance verdict            │
                    └─────────────────────────────────────┘
```

**Key insight:** AI enters at creation time, never at runtime. The runtime stays
deterministic, auditable, and reproducible. But the creation velocity goes from
"weeks per jurisdiction" to "hours per jurisdiction."

### YC Pitch Angle

> "Adding a new jurisdiction used to take weeks of legal research and hand-coding.
> Our AI rule authoring pipeline ingests legislation and proposes scanner rules,
> mappings, and questionnaire questions in minutes. A legal reviewer validates them.
> The runtime stays deterministic — same input, same verdict, every time.
> We used AI to write the rules for our GDPR pack in 2 hours. It took 3 minutes
> to validate. That's the 100x speedup on jurisdiction creation."

### Implementation Phases

#### Phase A: RuleAuthor MVP (1-2 weeks)

- Add `attestlens propose-rules --jurisdiction <j> --source <url|file>` CLI command
- LLM call to extract obligations, propose rules, propose questions
- Output: `ProposedPackManifest` JSON
- Uses existing schema types (`RegulationPrinciple`, `RuleDefinition`, `MappingRule`)
- Start with one well-known jurisdiction (e.g., Singapore PDPA) to validate

#### Phase B: PackReviewer (1 week)

- Interactive CLI for reviewing proposed rules one by one
- Show AI confidence, citation, and diff against existing pack (if any)
- Approve/reject/edit per rule
- Output: `JurisdictionPackManifest` ready for the scanner

#### Phase C: PackCompiler + Registry (1 week)

- Compile reviewed proposals into executable packs
- Validate against Zod schemas
- Store in `~/.attestlens/jurisdictions/<j>/latest.json`
- `attestlens update-rules --source <url>` can fetch community packs

#### Phase D: Self-Service Jurisdiction Creation (ongoing)

- Users can run `attestlens propose-rules` on their own legislation
- Community-contributed packs
- Marketplace / registry for jurisdiction packs

### Risk & Mitigation

| Risk | Mitigation |
|---|---|
| AI hallucinates rules that don't match legislation | Human review step is mandatory. Every rule must cite specific legislation. Low-confidence proposals are flagged. |
| AI misses obligations | Gaps array in output. Reviewer sees what the AI couldn't extract. Human fills gaps. |
| Rules are technically wrong (bad regex, wrong severity) | PackCompiler validates against Zod schemas. Integration tests catch pattern errors. |
| YC asks "what if the AI is wrong?" | "The AI proposes, the human validates. The runtime is deterministic. Bad rules get caught in review, not in production." |

### What This Does NOT Change

- Scanner stays deterministic (zero LLM calls at runtime)
- Opinion engine stays deterministic
- Existing AU, US, EU packs stay as they are (validated by hand)
- All 502+ tests still pass
- MCP interface unchanged
- The `RegulationPrinciple` type (Phase 10 schema decoupling) makes this work cleanly

### What This DOES Change

- Adding a new jurisdiction goes from weeks to hours
- YC story becomes: "AI writes the rules, humans validate them, the runtime is deterministic"
- Clearway becomes the only compliance tool where the AI contribution is *auditable*
- Community/marketplace story emerges naturally
- The "68 hardcoded rules" objection becomes "68 seed rules, infinite AI-proposed, human-validated rules"

## Dependency on Phase 10 (Schema Decoupling)

The RuleAuthor pipeline works best with jurisdiction-agnostic schema types.
Phase 10 (Global Schema Decoupling) should land first or in parallel:

- `APPPrinciple` → `RegulationPrinciple` (already `z.string()`)
- `APPMapping` → `RegulationMapping` (already has `jurisdiction` field)
- `APPInfo` → per-jurisdiction principle registries

The `ProposedPackManifest` type naturally uses `RegulationPrinciple`, so it's
clean from day one if Phase 10 lands first.

If Phase 10 hasn't landed yet, RuleAuthor can still work — it just outputs
AU-style `APPPrinciple` values alongside `RegulationPrinciple` values, and
the PackCompiler maps them appropriately.