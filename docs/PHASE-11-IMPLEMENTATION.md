# Phase 11: Rule Authoring Pipeline — Implementation Spec

**Date:** 2026-05-01
**Status:** Ready for implementation
**Timebox:** 1-2 weeks (Phases A-D, shipping A+B+C as MVP demo)
**Research base:** `docs/RESEARCH-PHASE-10.5-11.md`, `docs/RULE-AUTHORING-PIPELINE.md`

---

## Overview

Build the AI-assisted rule authoring pipeline. This is Clearway's moat: legislation goes in → AI drafts rules → human validates → deterministic runtime executes. The scanner NEVER calls an LLM. AI only enters at rule creation time.

**Demo goal:** Feed Singapore PDPA legislation text → AI proposes rules → human reviews → approved rules load into scanner → scan a project with the new rules.

---

## Step 1: AuthoredRule Schema

### What to build

Extend the existing `RuleDefinition` with provenance, interpretation, and test fields. Create a new `AuthoredRule` type alongside `RuleDefinition` (don't break existing schema).

### File changes

- `src/schema/index.ts` — Add `AuthoredRule`, `RuleProvenance`, `RuleInterpretation`, `RuleTestCase`, `ProposedPackManifest` Zod schemas

### Schema definitions

```typescript
// ─── Authored Rule (AI-Assisted) ─────────────────────────────────────────

export const RuleAuthorStage = z.enum(['ai-draft', 'human-validated', 'community']);
export type RuleAuthorStage = z.infer<typeof RuleAuthorStage>;

export const RuleConfidence = z.enum(['high', 'medium', 'low']);
export type RuleConfidence = z.infer<typeof RuleConfidence>;

export const RuleDeterminism = z.enum(['deterministic', 'heuristic', 'manual-only']);
export type RuleDeterminism = z.infer<typeof RuleDeterminism>;

export const RuleProvenance = z.object({
  draftedByModel: z.string().optional(),        // e.g., "gpt-5.5"
  draftedAt: z.string().datetime().optional(),  // ISO timestamp
  draftingPromptVersion: z.string().optional(), // Version of the drafting prompt
  sourceDocumentHash: z.string(),               // SHA-256 of legislation text used
  approvedBy: z.string().optional(),            // Reviewer identifier
  approvedAt: z.string().datetime().optional(), // ISO timestamp
  packVersion: z.string().optional(),           // Pack version when released
});
export type RuleProvenance = z.infer<typeof RuleProvenance>;

export const RuleInterpretation = z.object({
  machineCheckable: z.boolean(),                // Can this be deterministically checked?
  determinism: RuleDeterminism,                 // How reliable is the automated check?
  reviewRequired: z.boolean(),                  // Always true for ai-draft
  falsePositiveRisk: z.enum(['low', 'medium', 'high']),
});
export type RuleInterpretation = z.infer<typeof RuleInterpretation>;

export const RuleTestCase = z.object({
  name: z.string(),
  input: z.string(),                           // Code/config snippet to test
  shouldTrigger: z.boolean(),                   // True = positive test, False = negative test
  description: z.string().optional(),
});
export type RuleTestCase = z.infer<typeof RuleTestCase>;

export const AuthoredRule = RuleDefinition.extend({
  source: z.object({
    jurisdiction: Jurisdiction,
    citation: z.string(),                       // "Privacy Act 1988 (Cth) Schedule 1, APP 11.1"
    legislationUrl: z.string().optional(),      // Link to official source
    effectiveDate: z.string().optional(),       // When this version of the law takes effect
  }),
  authoring: z.object({
    author: RuleAuthorStage,
    confidence: RuleConfidence,
    falsePositiveRisk: z.enum(['low', 'medium', 'high']),
  }),
  provenance: RuleProvenance,
  interpretation: RuleInterpretation,
  tests: z.object({
    positive: z.array(RuleTestCase).default([]),
    negative: z.array(RuleTestCase).default([]),
    edgeCase: z.array(RuleTestCase).default([]),
  }),
});
export type AuthoredRule = z.infer<typeof AuthoredRule>;
```

### Proposed Pack Manifest

```typescript
export const ProposedPackManifest = z.object({
  schemaVersion: z.literal('3.0'),
  jurisdiction: Jurisdiction,
  generatedAt: z.string().datetime(),
  sourceDocumentHash: z.string(),               // SHA-256 of input legislation
  sourceDocumentUrl: z.string().optional(),
  principles: z.array(z.object({
    id: RegulationPrinciple,
    shortName: z.string(),
    fullName: z.string().optional(),
    obligation: z.string(),
    citation: z.string().optional(),
  })),
  rules: z.array(AuthoredRule),
  mappingRules: z.array(RegulationMapping).default([]),
  questions: z.array(Question).default([]),
  confidence: RuleConfidence,                    // Overall pack confidence
  warnings: z.array(z.string()).default([]),     // AI warnings about gaps
  gaps: z.array(z.string()).default([]),        // Areas where legislation is ambiguous
});
export type ProposedPackManifest = z.infer<typeof ProposedPackManifest>;
```

### Validated Pack Manifest

When a human approves a proposed pack, it becomes a `ValidatedPackManifest`:

```typescript
export const ValidatedPackManifest = JurisdictionPackManifest.extend({
  schemaVersion: z.literal('2.1'),              // Bump from 2.0
  provenance: z.object({
    proposedAt: z.string().datetime(),
    reviewedBy: z.string(),
    reviewedAt: z.string().datetime(),
    sourceDocumentHash: z.string(),
  }),
  ruleProvenance: z.record(z.string(), RuleProvenance).default({}), // Keyed by rule ID
});
export type ValidatedPackManifest = z.infer<typeof ValidatedPackManifest>;
```

### Key constraints

- `AuthoredRule` extends `RuleDefinition` — backward compatible, existing rules work as-is
- `ProposedPackManifest` is schema version 3.0 (new artifact, doesn't break 2.0 packs)
- `ValidatedPackManifest` extends `JurisdictionPackManifest` (schema 2.1) — the scanner can load both 2.0 and 2.1 packs
- AI-drafted rules MUST have `authoring.author === 'ai-draft'` and `authoring.confidence` set
- AI-drafted rules MUST have `interpretation.reviewRequired === true`

### Tests

- Unit test: AuthoredRule schema validation (valid, invalid, missing provenance)
- Unit test: ProposedPackManifest schema validation
- Unit test: ValidatedPackManifest schema validation
- Unit test: AuthoredRule is compatible with RuleDefinition (can be used where RuleDefinition is expected)

---

## Step 2: Deterministic Test Harness

### What to build

A test runner that validates proposed rules against fixture files. Each rule has positive/negative/edge-case tests. The harness runs the rule against each fixture and verifies the result matches expectations.

### File changes

- `src/authoring/test-harness.ts` — New file: rule test runner

### API

```typescript
interface TestHarnessOptions {
  rules: AuthoredRule[];
  basePath?: string;            // Base path for resolving fixture files
  fixtureDir?: string;          // Directory containing fixture files
}

interface TestHarnessResult {
  ruleId: string;
  passed: boolean;
  results: Array<{
    testName: string;
    category: 'positive' | 'negative' | 'edgeCase';
    input: string;
    shouldTrigger: boolean;
    didTrigger: boolean;
    passed: boolean;
    error?: string;
  }>;
  summary: {
    total: number;
    passed: number;
    failed: number;
  };
}

async function runRuleTestHarness(options: TestHarnessOptions): Promise<TestHarnessResult[]>;
```

### How it works

For each rule:
1. Load the rule's test cases (positive, negative, edgeCase)
2. For each test case:
   - Create a temp file with the test `input` string
   - Run the scanner with ONLY this rule enabled (pass `--include-rule <id>` or filter rules programmatically)
   - Check if the rule triggered (`didTrigger`)
   - Compare against `shouldTrigger`
   - Record pass/fail
3. Aggregate results per rule

**Important:** The scanner must run deterministically. No network access, no LLM calls. The test harness runs the SAME scanner code that runs in production CI.

### Fixture handling

- Inline fixtures: test `input` is a string embedded in the `RuleTestCase`
- File fixtures: test `input` is a path relative to `fixtureDir`
- The harness creates temp directories, writes inline fixtures, scans them, and cleans up

### Tests

- Unit test: harness with a known-good rule + test cases → all pass
- Unit test: harness with a known-bad rule (wrong pattern) → some fail
- Unit test: harness with no test cases → empty results
- Unit test: harness with mixed positive/negative cases

---

## Step 3: AI Drafting Flow

### What to build

A CLI command `attestlens propose-rules` that takes legislation text, calls an LLM, and produces a `ProposedPackManifest`.

### CLI command

```bash
attestlens propose-rules \
  --jurisdiction sg-pdpa \
  --source ./PDPA-2012.txt \
  --source-url "https://sso.agc.gov.sg/Act/PDPA2012" \
  --output ./proposed-sg-pdpa.json \
  --model gpt-5.5
```

Options:
- `--jurisdiction <j>` — Target jurisdiction (required)
- `--source <path>` — Path to legislation text file (required)
- `--source-url <url>` — URL to official legislation source (optional)
- `--output <path>` — Output path for proposed pack JSON (required)
- `--model <model>` — LLM model to use (default: `gpt-5.5`)
- `--api-key <key>` — API key (or set `OPENAI_API_KEY` env var)
- `--base-url <url>` — Custom API base URL (for non-OpenAI providers)
- `--existing-pack <path>` — Path to existing pack to diff against (optional)

### File changes

- `src/authoring/propose.ts` — New file: rule proposal engine
- `src/authoring/prompt.ts` — New file: LLM prompt templates
- `src/cli/index.ts` — Register `propose-rules` subcommand

### LLM prompt strategy

The drafting prompt should produce structured JSON, not free text. Use a two-pass approach:

**Pass 1: Extract Obligations**
- Input: legislation text
- Output: list of obligations with citations, principles, and checkability assessment

**Pass 2: Generate Rules**
- Input: obligations from Pass 1
- Output: proposed scanner rules with patterns, severities, mappings, test cases

**Prompt template (Pass 1):**

```
You are a privacy law analyst. Extract all machine-checkable obligations from the following legislation text.

For each obligation, provide:
1. principleId: A short identifier (e.g., "SGPDPA_Consent_1")
2. shortName: Human-readable name
3. obligation: The specific legal obligation text
4. citation: Exact citation (section, paragraph)
5. machineCheckable: Can this be verified by scanning code/config? (true/false)
6. determinism: "deterministic" if the check is unambiguous, "heuristic" if it requires judgment, "manual-only" if it cannot be automated
7. falsePositiveRisk: "low", "medium", or "high"

Respond as a JSON array. Only include obligations that could reasonably be checked by scanning source code, configuration files, or web pages.
```

**Prompt template (Pass 2):**

```
You are a security rule author. Based on the following obligations, write scanner rules.

For each obligation where machineCheckable is true, create a rule:
1. id: Rule ID (e.g., "SGPDPA-CONSENT-001")
2. category: Rule category
3. severity: "error", "warning", or "note" based on the legal consequence
4. title: Short rule title
5. description: What the rule checks and why
6. pattern: Regex or glob pattern to detect violations (if applicable)
7. flags: Regex flags (if applicable)
8. tags: Relevant tags
9. regulationMappings: Map to the principle
10. testCases: At least one positive and one negative test case

For obligations where machineCheckable is false, add them to the "gaps" array.

Respond as a JSON object matching the ProposedPackManifest schema.
```

### API design

```typescript
interface ProposeRulesOptions {
  jurisdiction: Jurisdiction;
  legislationText: string;
  legislationUrl?: string;
  model?: string;
  apiKey?: string;
  baseUrl?: string;
  existingPack?: JurisdictionPackManifest;
}

interface ProposeRulesResult {
  proposed: ProposedPackManifest;
  duration: number;
  tokensUsed?: number;
  model: string;
}

async function proposeRules(options: ProposeRulesOptions): Promise<ProposeRulesResult>;
```

### Security constraints

- API key must NOT be logged, stored in output files, or included in SARIF
- The `propose-rules` command is SEPARATE from the scanner — it never runs during CI scans
- LLM calls happen ONLY in `propose-rules`, never in `scan`/`audit`/`opinion`
- The `sourceDocumentHash` in the output is SHA-256 of the input legislation text — this enables reproducibility
- All proposed rules get `authoring.author: 'ai-draft'` and `interpretation.reviewRequired: true`

### Output format

The `--output` file is a `ProposedPackManifest` JSON with full provenance. Example:

```json
{
  "schemaVersion": "3.0",
  "jurisdiction": "sg-pdpa",
  "generatedAt": "2026-05-01T10:00:00Z",
  "sourceDocumentHash": "sha256:abc123...",
  "sourceDocumentUrl": "https://sso.agc.gov.sg/Act/PDPA2012",
  "principles": [
    {
      "id": "SGPDPA_Consent",
      "shortName": "Consent",
      "obligation": "Organizations must obtain consent before collecting personal data",
      "citation": "PDPA 2012, Part III, Section 13"
    }
  ],
  "rules": [
    {
      "id": "SGPDPA-CONSENT-001",
      "category": "Consent",
      "severity": "high",
      "title": "Consent mechanism missing",
      "description": "No consent collection mechanism detected",
      "pattern": "...",
      "source": {
        "jurisdiction": "sg-pdpa",
        "citation": "PDPA 2012, Part III, Section 13"
      },
      "authoring": {
        "author": "ai-draft",
        "confidence": "medium",
        "falsePositiveRisk": "medium"
      },
      "provenance": {
        "draftedByModel": "gpt-5.5",
        "draftedAt": "2026-05-01T10:00:00Z",
        "draftingPromptVersion": "1.0",
        "sourceDocumentHash": "sha256:abc123..."
      },
      "interpretation": {
        "machineCheckable": true,
        "determinism": "heuristic",
        "reviewRequired": true,
        "falsePositiveRisk": "medium"
      },
      "tests": {
        "positive": [
          { "name": "no-consent-form", "input": "...", "shouldTrigger": true }
        ],
        "negative": [
          { "name": "has-consent-form", "input": "...", "shouldTrigger": false }
        ],
        "edgeCase": []
      }
    }
  ],
  "confidence": "medium",
  "warnings": ["AI confidence is medium — human review recommended"],
  "gaps": ["Data protection officer appointment (Section 11) cannot be checked by code scanning"]
}
```

### Tests

- Unit test: `proposeRules()` with mock LLM response → valid ProposedPackManifest
- Unit test: schema validation of LLM output (reject invalid responses gracefully)
- Unit test: `sourceDocumentHash` matches SHA-256 of input text
- Unit test: all proposed rules have `authoring.author: 'ai-draft'`
- Integration test (optional): real LLM call with SG PDPA text → produces valid output

---

## Step 4: Human Approval Flow

### What to build

A CLI command `attestlens review-pack` that loads a proposed pack and lets a human review each rule interactively.

### CLI command

```bash
attestlens review-pack \
  --proposed ./proposed-sg-pdpa.json \
  --reviewer "Vincent Peng" \
  --output ./reviewed-sg-pdpa.json
```

Options:
- `--proposed <path>` — Path to ProposedPackManifest JSON (required)
- `--reviewer <name>` — Reviewer identifier (required)
- `--output <path>` — Output path for validated pack JSON (required)
- `--approve-all` — Approve all rules without interactive review (DANGEROUS — for testing only)
- `--reject-low-confidence` — Auto-reject rules with confidence=low

### Interactive review flow

For each proposed rule:

1. Display the rule:
   - ID, title, description
   - Severity, confidence, determinism
   - Citation and source
   - Test cases (positive/negative)
   - AI warnings

2. Run the test harness on this rule (show pass/fail)

3. Prompt the reviewer:
   - `[a]pprove` — Accept rule as-is
   - `[e]dit` — Open in editor to modify before approving
   - `[r]eject` — Remove from pack
   - `[s]kip` — Defer decision (excluded from output)
   - `[v]iew` — Show full rule JSON
   - `[q]uit` — Save progress and exit

4. Record the decision:
   - Approved rules: set `authoring.author: 'human-validated'`, add `provenance.approvedBy` and `provenance.approvedAt`
   - Rejected rules: excluded from output
   - Skipped rules: excluded from output

### File changes

- `src/authoring/review.ts` — New file: interactive review flow
- `src/cli/index.ts` — Register `review-pack` subcommand

### Output format

The output is a `ValidatedPackManifest` (schema 2.1) that the scanner can load. It contains only approved rules with full provenance.

### Key constraint

**AI-drafted rules that are NOT reviewed MUST NOT enter the scanner.** The `ValidatedPackManifest` requires `provenance.reviewedBy` and `provenance.reviewedAt`. The scanner will refuse to load packs without review provenance when `authoring.author === 'ai-draft'`.

### Tests

- Unit test: `reviewPack()` with approve-all → valid ValidatedPackManifest
- Unit test: rejected rules excluded from output
- Unit test: `provenance.approvedBy` and `provenance.approvedAt` populated
- Unit test: `authoring.author` changes from 'ai-draft' to 'human-validated' on approval
- Unit test: unreviewed ai-draft rules are rejected by scanner

---

## Step 5: Pack Versioning + Scanner Integration

### What to build

Make the scanner load validated packs alongside the existing embedded packs. Add pack versioning so updates don't break existing installations.

### How packs are loaded

Current flow:
1. Scanner loads embedded rules from `src/scanner/rules/embedded.ts`
2. Optional: load cached rules from `~/.attestlens/cache/`

New flow:
1. Scanner loads embedded rules (unchanged)
2. Optional: load validated packs from `~/.attestlens/jurisdictions/<jurisdiction>/latest.json`
3. Validated packs extend (not replace) embedded rules
4. If a validated pack has rules with the same ID as embedded rules, the validated pack takes precedence (allows updates)

### File changes

- `src/scanner/rules/index.ts` — Add `loadValidatedJurisdictionPack()` function
- `src/scanner/orchestrator.ts` — Load validated packs alongside embedded rules

### Pack discovery

```typescript
function getJurisdictionPackPath(jurisdiction: Jurisdiction): string | null {
  const packPath = path.join(
    os.homedir(),
    '.attestlens',
    'jurisdictions',
    jurisdiction,
    'latest.json'
  );
  return existsSync(packPath) ? packPath : null;
}
```

### Scanner behavior with validated packs

When a validated pack is loaded:
- Log the pack version, review provenance, and rule count
- Merge rules: validated pack rules override embedded rules with the same ID
- AI-drafted rules with `authoring.author === 'ai-draft'` are **skipped** (not loaded into scanner)
- Only `human-validated` rules from the pack are loaded
- This is enforced at load time, not just at review time

### Version conflict handling

If a validated pack version is older than the embedded pack version for the same jurisdiction:
- Log a warning: "Validated pack v1.0 is older than embedded pack v0.4.0"
- Use the embedded pack (newer = trusted)
- Suggest re-running `propose-rules` with `--existing-pack`

### Tests

- Unit test: load validated pack alongside embedded rules
- Unit test: validated pack rules override embedded rules with same ID
- Unit test: ai-draft rules in validated pack are skipped
- Unit test: older validated pack produces warning, embedded pack wins
- Integration test: `attestlens scan --jurisdiction sg-pdpa` with a validated SG PDPA pack

---

## Step 6: Confidence-Based Release Gates

### What to build

Enforce confidence-based behavior in the scanner: high-confidence rules are blocking, medium are advisory, low are informational.

### File changes

- `src/scanner/orchestrator.ts` — Apply confidence-based severity override

### Behavior matrix

| Author | Confidence | Determinism | Default Behavior |
|--------|-----------|-------------|-----------------|
| human-validated | high | deterministic | Blocking (severity as-is) |
| human-validated | medium | heuristic | Advisory (downgrade error→warning) |
| human-validated | low | manual-only | Informational (downgrade to note) |
| ai-draft | any | any | **NEVER loaded into scanner** |

### Implementation

When loading a rule from a validated pack:

```typescript
function resolveEffectiveSeverity(rule: AuthoredRule): Severity {
  // AI-draft rules should never reach this point (filtered at load time)
  if (rule.authoring.author === 'ai-draft') {
    throw new Error(`AI-draft rule ${rule.id} must not be loaded into scanner`);
  }

  const { confidence, falsePositiveRisk } = rule.authoring;
  const { determinism } = rule.interpretation;

  // High confidence, deterministic → keep original severity
  if (confidence === 'high' && determinism === 'deterministic') {
    return rule.severity;
  }

  // Medium confidence or heuristic → cap at 'warning'
  if (confidence === 'medium' || determinism === 'heuristic') {
    return capSeverity(rule.severity, 'medium');
  }

  // Low confidence or manual-only → cap at 'info'
  return 'info';
}
```

### Tests

- Unit test: high-confidence deterministic rule keeps original severity
- Unit test: medium-confidence heuristic rule capped at 'medium'
- Unit test: low-confidence manual-only rule capped at 'info'
- Unit test: ai-draft rule throws error if loaded

---

## Step 7: `propose-rules` Demo with SG PDPA

### What to build

A working end-to-end demo that:
1. Takes the SG PDPA legislation text as input
2. Calls the LLM to propose rules
3. Writes a `ProposedPackManifest` JSON
4. Reviewer approves via `review-pack`
5. Approved rules load into scanner
6. `attestlens scan --jurisdiction sg-pdpa` works with the new rules

### Demo script

Create `demo/rule-authoring.sh` that walks through the full flow:

```bash
#!/bin/bash
set -e
echo "=== Clearway Rule Authoring Pipeline Demo ==="
echo ""
echo "Step 1: Propose rules from SG PDPA legislation"
attestlens propose-rules \
  --jurisdiction sg-pdpa \
  --source demo/sg-pdpa-2012.txt \
  --source-url "https://sso.agc.gov.sg/Act/PDPA2012" \
  --output /tmp/proposed-sg-pdpa.json

echo ""
echo "Step 2: Review proposed rules (auto-approve for demo)"
attestlens review-pack \
  --proposed /tmp/proposed-sg-pdpa.json \
  --reviewer "demo-reviewer" \
  --approve-all \
  --output ~/.attestlens/jurisdictions/sg-pdpa/latest.json

echo ""
echo "Step 3: Scan with the new jurisdiction pack"
attestlens scan demo/test-project --jurisdiction sg-pdpa

echo ""
echo "=== Demo Complete ==="
```

### Demo assets

- `demo/sg-pdpa-2012.txt` — Excerpt of Singapore PDPA 2012 (key sections: Part III Consent, Part IV Purpose, Part V Access, Part VI Correction, Part XVIII Data Protection)
- `demo/test-project/` — Simple project with intentional violations (missing consent form, no privacy policy, etc.)

### Tests

- Integration test: full propose → review → scan flow with mock LLM
- The demo script should work with a real API key for YC presentation

---

## Implementation Order

1. **Step 1** (AuthoredRule schema) — Foundation everything depends on
2. **Step 2** (Test harness) — Needed before reviewing rules
3. **Step 3** (AI drafting) — The core AI feature
4. **Step 4** (Human approval) — The safety gate
5. **Step 5** (Pack versioning + scanner integration) — Makes approved rules usable
6. **Step 6** (Confidence gates) — Enforcement layer
7. **Step 7** (Demo) — The YC pitch closer

Steps 1-4 can be done sequentially. Step 5 and 6 depend on 1-4. Step 7 depends on everything.

---

## Testing Requirements

- All 542 existing tests must continue to pass
- New schema tests for AuthoredRule, ProposedPackManifest, ValidatedPackManifest
- New test harness tests
- New propose-rules tests (with mock LLM)
- New review-pack tests
- New scanner integration tests (loading validated packs)
- New confidence gate tests
- `tsc --noEmit` must be clean

---

## Security Checklist

- [ ] API keys never logged, stored in output, or included in SARIF
- [ ] LLM calls ONLY in `propose-rules`, never in scan/audit/opinion/MCP
- [ ] AI-draft rules NEVER loaded into scanner (enforced at load time)
- [ ] `sourceDocumentHash` enables reproducibility verification
- [ ] `provenance.approvedBy` is required for human-validated rules
- [ ] Confidence-based severity capping prevents AI-draft rules from being blocking
- [ ] `--approve-all` flag is clearly marked as DANGEROUS
- [ ] No network access during scanner execution (validated packs are local files)
- [ ] Pack version conflict detection prevents downgrade attacks