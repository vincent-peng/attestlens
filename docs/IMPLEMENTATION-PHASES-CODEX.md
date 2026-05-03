# Implementation Phases and Codex Prompts

**Purpose:** Give Codex or another AI coding agent enough detail to implement the international YC reset without ambiguity.  
**Instruction to coding agents:** Work phase-by-phase. Do not implement later phases until the earlier phase acceptance criteria pass.

---

## Phase 1 — Documentation and positioning reset

### Goal

Make the repo tell one clear story:

> Clearway is the deterministic privacy deploy gate for AI-generated software.

### Files to modify

- `README.md`
- `docs/YC-APPLICATION.md`
- `docs/INTERNATIONAL-STRATEGY.md`
- `docs/ROADMAP.md`
- `docs/PRICING.md`
- `docs/INDEX.md`
- Create `docs/DESIGN-PARTNER-VALIDATION.md`
- Create `docs/COMPETITIVE-POSITIONING-INTERNATIONAL.md`
- Create `docs/DOCS-CONSOLIDATION-PLAN.md`

### Requirements

- Remove or soften unverified claims such as “100K+ businesses newly liable” unless separately verified.
- Do not claim full global compliance.
- Do not claim legal advice.
- Use `npx -y --package @attestlens/cli@beta attestlens ...` commands.
- Explain pack maturity: AU deep, CCPA/GDPR coverage-bounded, SG beta.
- Explain deterministic runtime and human-validated rule promotion.

### Codex prompt

```text
You are editing the AttestLens/Clearway repo for an international YC application reset.

Objective: reposition the product as “the deterministic privacy deploy gate for AI-generated software,” not an AU-only scanner or generic compliance platform.

Modify these docs:
- README.md
- docs/YC-APPLICATION.md
- docs/INTERNATIONAL-STRATEGY.md
- docs/ROADMAP.md
- docs/PRICING.md
- docs/INDEX.md

Create these docs:
- docs/DESIGN-PARTNER-VALIDATION.md
- docs/COMPETITIVE-POSITIONING-INTERNATIONAL.md
- docs/DOCS-CONSOLIDATION-PLAN.md

Constraints:
- Do not claim “global compliance.” Use “multi-jurisdiction” and “coverage-bounded packs.”
- Do not claim legal advice.
- Correct all npm examples to use: npx -y --package @attestlens/cli@beta attestlens <command>
- Explain that AI can draft rules, but only human-validated rules can become blocking.
- Keep the README concise and demo-oriented.
- Archive old docs only by recommending moves in DOCS-CONSOLIDATION-PLAN.md unless you are explicitly asked to move files.

Acceptance criteria:
- A new reader understands the product in 60 seconds.
- The YC application doc has a strong international story without overclaiming.
- All commands are copy-paste plausible.
- The product does not sound like a generic privacy scanner clone.
```

---

## Phase 2 — Real CI deploy-gate workflow

### Goal

Make “deploy gate” real in the repo.

### Files to modify/create

- `.github/workflows/ci.yml`
- `.github/workflows/clearway-gate.yml`
- `examples/github-action/clearway.yml`
- `docs/CI-INTEGRATION.md`
- `docs/DEMO-SCRIPT.md`
- Optional: `demo/agent-pr-privacy-risk/`

### Requirements

- Test/build workflow must run `npm ci`, `npm run lint`, `npm test`, and `npm run build`.
- Clearway gate workflow must run the published CLI or local build.
- SARIF should be generated even when the scan finds blocking issues.
- Failure threshold must be separate from SARIF level.
- Add advisory-mode and blocking-mode examples.

### Recommended workflow behavior

For internal repo CI:

1. Build local package.
2. Run Clearway on repo in advisory mode first.
3. Upload SARIF when possible.
4. Use a demo fixture for a known failing case instead of making the whole repo fail forever.

### Codex prompt

```text
Implement real GitHub Actions workflows for Clearway.

Create:
1. .github/workflows/ci.yml
   - runs on push and pull_request
   - uses actions/checkout@v4
   - uses actions/setup-node@v4 with node-version 20
   - runs npm ci
   - runs npm run lint
   - runs npm test
   - runs npm run build

2. .github/workflows/clearway-gate.yml
   - runs on pull_request
   - builds the local package
   - runs Clearway in SARIF mode against the repo or demo fixture
   - writes clearway.sarif
   - uploads SARIF with github/codeql-action/upload-sarif@v4 when permissions allow
   - demonstrates both advisory and blocking modes in comments

3. examples/github-action/clearway.yml
   - copy-paste workflow for users
   - includes advisory mode and strict blocking mode examples
   - uses npx -y --package @attestlens/cli@beta attestlens audit .

4. docs/DEMO-SCRIPT.md
   - 60-second YC demo: agent introduces privacy-risky code, Clearway blocks, agent fixes, gate passes.

Constraints:
- Do not break the repo by making main branch permanently fail.
- SARIF upload should use if: always() so results are uploaded even if scan exits non-zero.
- Use minimal GitHub token permissions: contents: read and security-events: write.
- Keep commands consistent with package.json binaries.

Acceptance criteria:
- GitHub Actions YAML is syntactically valid.
- npm scripts referenced exist in package.json.
- docs/CI-INTEGRATION.md reflects the new workflows.
- There is a reproducible demo gate flow.
```

---

## Phase 3 — Jurisdiction pack trust and coverage metadata

### Goal

Make international claims credible by making coverage boundaries and validation status first-class.

### Files likely to modify

- `src/schema/index.ts`
- `src/scanner/rules/embedded.ts`
- `src/scanner/rules/loader.ts`
- `src/report/generator.ts`
- `src/opinion/engine.ts` or opinion-related files
- `src/mcp/index.ts`
- tests under `src/**/*.test.ts`

### New schema proposal

Add to jurisdiction pack manifests:

```ts
export const PackValidationStatus = z.enum([
  'draft',
  'internal_validated',
  'external_reviewed',
  'customer_validated',
  'legal_partner_validated',
]);

export const JurisdictionCoverage = z.object({
  summary: z.string(),
  includedPrinciples: z.array(RegulationPrinciple),
  excludedPrinciples: z.array(RegulationPrinciple).default([]),
  knownGaps: z.array(z.string()).default([]),
  evidenceTypes: z.array(z.string()).default([]),
});

export const PackValidation = z.object({
  status: PackValidationStatus,
  reviewedBy: z.string().optional(),
  reviewedAt: z.string().datetime().optional(),
  notes: z.array(z.string()).default([]),
});
```

Add optional fields first for backward compatibility, then populate embedded packs.

### Behavior changes

- Reports must display coverage and validation state.
- Agent output must include `packValidationStatus`.
- Opinion engine must avoid broad `COMPLIANT` for packs below `external_reviewed` unless the verdict is scoped to “no in-scope blocking findings.”
- High-confidence blocking requires:
  - deterministic rule,
  - validated pack,
  - high confidence,
  - severity threshold met.

### Codex prompt

```text
Implement jurisdiction pack trust metadata for Clearway.

Goal: make international packs credible by adding coverage boundaries and validation status to every jurisdiction pack and report.

Modify schema/index.ts:
- Add PackValidationStatus enum: draft, internal_validated, external_reviewed, customer_validated, legal_partner_validated.
- Add JurisdictionCoverage schema with summary, includedPrinciples, excludedPrinciples, knownGaps, evidenceTypes.
- Add PackValidation schema with status, reviewedBy, reviewedAt, notes.
- Extend JurisdictionPackManifest and ValidatedPackManifest to include optional coverage and validation fields. Keep backward compatibility.

Modify embedded packs:
- AU pack: validation.status = internal_validated; coverage lists APP/NDB scope and known limitations.
- CCPA pack: validation.status = draft or internal_validated depending on current tests; coverage explicitly says subset.
- GDPR pack: validation.status = draft or internal_validated; coverage explicitly says subset, not full GDPR.
- SG PDPA: validation.status = draft; coverage says beta/stub.

Modify reports and agent output:
- Include pack validation status.
- Include coverage summary and known gaps.
- Do not emit broad COMPLIANT wording for draft/internal-only packs. Prefer PASS_NO_IN_SCOPE_BLOCKERS or NEEDS_REVIEW where appropriate.

Modify tests:
- Add tests that each embedded pack has coverage and validation metadata.
- Add tests that draft packs cannot produce overbroad COMPLIANT language.
- Add tests that report JSON includes validation status and coverage.

Acceptance criteria:
- npm test passes.
- npm run lint passes.
- Existing MCP schemas remain backward-compatible.
- Agent output includes pack validation and coverage fields.
```

---

## Phase 4 — Operational verdict model

### Goal

Move from legal-sounding compliance conclusions to deploy-gate decisions.

### Files likely to modify

- `src/schema/index.ts`
- `src/opinion/engine.ts`
- `src/report/generator.ts`
- `src/mcp/index.ts`
- `src/formatters/sarif.ts`

### New verdict model

```ts
export const DeployVerdict = z.enum([
  'BLOCK',
  'WARN',
  'NEEDS_REVIEW',
  'PASS',
  'OUT_OF_SCOPE',
]);
```

Keep old compliance opinion fields for backward compatibility, but add deploy-specific output.

### Decision logic

- `BLOCK`: high-confidence deterministic finding from validated pack at/above blocking threshold.
- `WARN`: medium-confidence or advisory finding.
- `NEEDS_REVIEW`: context/evidence required or legal conclusion cannot be automated.
- `PASS`: no in-scope blocking or warning findings.
- `OUT_OF_SCOPE`: selected pack cannot assess the relevant obligation.

### Codex prompt

```text
Add an operational DeployVerdict model to Clearway.

Goal: reports and agent output should answer “should this change be allowed to ship?” without overclaiming legal compliance.

Add schema:
- DeployVerdict enum: BLOCK, WARN, NEEDS_REVIEW, PASS, OUT_OF_SCOPE.
- DeployDecision object with verdict, blocking, confidence, jurisdiction, packValidationStatus, reasons, evidenceRefs, remediations.

Modify opinion/report generation:
- Preserve existing ComplianceOpinion for backward compatibility.
- Add deployDecision to reports when --opinion is used.
- In agent format, make deployDecision the primary field.

Decision rules:
- BLOCK only when a high-confidence deterministic finding meets threshold and the pack validation status allows blocking.
- WARN for advisory/medium-confidence issues.
- NEEDS_REVIEW for legal/contextual evidence gaps.
- PASS means no in-scope blocking findings, not legal compliance.
- OUT_OF_SCOPE when the pack declares a relevant gap.

Modify SARIF formatter:
- Map BLOCK to error.
- Map WARN to warning.
- Map NEEDS_REVIEW to warning or note depending on severity.
- Avoid security-severity unless the finding is truly security-related.

Tests:
- high-confidence issue produces BLOCK.
- draft pack issue does not produce BLOCK unless explicitly allowed.
- no findings produces PASS, not COMPLIANT.
- agent output includes deployDecision.

Acceptance criteria:
- Backward-compatible JSON output.
- Agent output is more deploy-oriented than legal-oriented.
- Tests pass.
```

---

## Phase 5 — PR diff mode

### Goal

Assess what an agent changed, not only the entire repo.

### Files likely to modify

- `src/cli/index.ts`
- `src/scanner/orchestrator.ts`
- new `src/git/diff.ts`
- `src/report/generator.ts`
- `src/mcp/index.ts`
- tests

### CLI proposal

```bash
attestlens audit . --diff-base origin/main --diff-head HEAD --jurisdiction eu-gdpr --format agent
```

### Output additions

```ts
pullRequestContext?: {
  baseRef?: string;
  headRef?: string;
  changedFiles: string[];
  addedDependencies: string[];
  addedRoutes: string[];
  introducedFindings: string[];
}
```

### Codex prompt

```text
Implement PR diff mode for Clearway.

Goal: Clearway should prioritize issues introduced by the current PR or agent change.

Add CLI flags to audit and scan:
- --diff-base <ref>
- --diff-head <ref>
- --changed-files-only

Implement src/git/diff.ts:
- getChangedFiles(base, head): uses git diff --name-only safely via execFile, not shell.
- getAddedLines or changed hunks if feasible; otherwise start with changed file filtering.
- detectAddedDependencies by comparing package.json/package-lock changes.
- detect likely added routes/endpoints for Next.js/Express/Hono where simple.

Modify scanner orchestration:
- If --changed-files-only is passed, restrict static scanning to changed files when possible.
- Otherwise scan whole repo but annotate findings whose file is changed.

Modify finding/report schema:
- Add introducedInDiff?: boolean.
- Add diffContext to report metadata.

Modify agent output:
- Sort introduced findings first.
- Include changedFiles and introducedFindings summary.

MCP:
- Add optional diffBase/diffHead/chosen changedFiles fields to scan/audit input schemas.

Tests:
- Mock git diff output.
- Verify changed-file findings are annotated introducedInDiff.
- Verify unchanged findings sort lower in agent output.

Acceptance criteria:
- Existing full scan behavior unchanged when no diff flags are provided.
- Diff mode works in GitHub Actions pull_request context.
- No shell injection: use execFile with args only.
```

---

## Phase 6 — Evidence graph lite

### Goal

Create a durable moat: every verdict has an evidence chain.

### Files likely to modify

- `src/schema/index.ts`
- `src/report/generator.ts`
- `src/opinion/engine.ts`
- scanner adapters as needed

### Schema proposal

```ts
export const EvidenceNode = z.object({
  id: z.string(),
  type: z.enum(['finding', 'questionnaire', 'source_file', 'url', 'dependency', 'manual_attestation', 'pack_rule']),
  title: z.string(),
  location: z.string().optional(),
  hash: z.string().optional(),
  metadata: z.record(z.unknown()).default({}),
});

export const EvidenceChain = z.object({
  id: z.string(),
  claim: z.string(),
  nodes: z.array(EvidenceNode),
  controls: z.array(RegulationPrinciple),
  jurisdiction: Jurisdiction,
  confidence: OpinionConfidence,
});
```

### Codex prompt

```text
Implement Evidence Graph Lite for Clearway reports.

Goal: every deploy decision and opinion should be traceable to evidence nodes.

Add schema types:
- EvidenceNode
- EvidenceChain

Modify report generation:
- Build evidence chains from findings, questionnaire responses, and pack rules.
- Each key finding should produce at least one EvidenceNode.
- Each control/opinion should reference evidence chain IDs.

Modify agent output:
- Include compact evidenceChains array.
- For each deployDecision reason, include evidenceRefs.

Constraints:
- Store evidence in local report JSON only. Do not build hosted storage.
- Do not include raw secrets or full sensitive data values. Reuse existing redaction.
- Keep output size reasonable for agent format.

Tests:
- A finding maps to an evidence node.
- A compliance/deploy opinion references evidenceRefs.
- Redacted sensitive values remain redacted.

Acceptance criteria:
- Reports become auditable without becoming legal opinions.
- Agent output can cite evidence to a user.
```

---

## Phase 7 — Taint-lite data flow

### Goal

Improve technical depth against privacy-scanner competitors without trying to rebuild full static taint tracking.

### Files likely to modify/create

- `src/scanner/data-flow-lite.ts`
- `src/scanner/orchestrator.ts`
- `src/schema/index.ts`
- `src/scanner/rules/*`
- tests

### Scope

Detect simple source-to-sink flows:

Sources:

- form fields: email, phone, name, address, DOB, health, payment, government ID,
- request body fields,
- database columns,
- schema definitions,
- TypeScript interfaces or Zod schemas.

Sinks:

- console/logging,
- analytics/tracking SDKs,
- external fetch/axios calls,
- LLM prompt construction,
- database writes,
- email/SMS providers.

### Codex prompt

```text
Implement Data Flow Lite for Clearway.

Goal: detect obvious PII source-to-sink risks with high precision, not full taint tracking.

Create src/scanner/data-flow-lite.ts adapter.

Detect sources:
- Zod schemas with fields like email, phone, name, address, dateOfBirth, health, ssn, nric, medicare, payment, card.
- TypeScript interfaces/types with same field names.
- Express/Hono/Next route handlers reading req.body or request.json().

Detect sinks:
- console.log/debug/info with source-like fields.
- analytics calls: posthog, segment, mixpanel, amplitude, google analytics.
- external fetch/axios with source-like payloads.
- OpenAI/Anthropic/LLM prompt strings containing source-like fields.

Output findings:
- DATAFLOW-PII-LOG
- DATAFLOW-PII-ANALYTICS
- DATAFLOW-PII-EXTERNAL
- DATAFLOW-PII-LLM

Confidence rules:
- High only when source and sink are in same function/file with direct variable/field reference.
- Medium when same file but indirect.
- Low/NEEDS_REVIEW when only names suggest a flow.

Constraints:
- Do not overreport. Prefer fewer high-quality findings.
- Redact sample values.
- Add regulationMappings to relevant jurisdiction controls through mapping engine.

Tests:
- Detect email logged in same route.
- Detect phone sent to analytics.
- Detect health data sent to LLM prompt.
- Do not flag unrelated variable names or placeholder docs.

Acceptance criteria:
- High precision on fixtures.
- Findings include confidence and evidence.
- Can be disabled with --no-data-flow-lite if noisy.
```

---

## Phase 8 — Hosted evidence and paid tier

### Goal

Only after pilots: build monetizable retention and team workflow.

### Codex prompt

```text
Do not implement this phase until there is at least one design partner or paid pilot.

When approved, design hosted/private evidence retention for Clearway.

Requirements:
- Keep local-first runtime.
- Add optional upload of sanitized reports.
- Add team policy settings.
- Add suppression workflow with reviewer and reason.
- Add trend view by jurisdiction, principle, and repo.
- Add approval records for NEEDS_REVIEW findings.

Do not add a dashboard until customer pull is clear.
```

---

## Cross-phase engineering principles

- Use `execFile`, never shell interpolation.
- Keep scanner runtime deterministic.
- Do not call LLMs during scan/audit runtime.
- Redact sensitive values in reports.
- Maintain MCP structuredContent compatibility.
- Preserve backward-compatible JSON fields until a major version bump.
- Keep `agent` format compact.
- Never imply legal advice.
