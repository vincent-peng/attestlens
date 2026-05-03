# Roadmap — International Agent Privacy Gate

**Status:** Replace older roadmap with this reset.  
**Core decision:** Continue, but stop building broad features until validation proves the gate.  
**North star:** Clearway becomes the default policy gate for AI agents that touch customer data.

---

## Current product baseline

Already shipped or mostly shipped:

- CLI and npm package.
- MCP server with 8 tools.
- SARIF output and exit-threshold controls.
- Deterministic opinion engine.
- AU, CCPA, GDPR, SG PDPA jurisdiction packs in varying maturity.
- AI-assisted rule-authoring pipeline with human review.
- Local/offline-first runtime.

Main gap:

> Customer validation is weaker than implementation progress.

Therefore, the next roadmap must prioritize validation and deploy-gate proof over new feature breadth.

---

## Roadmap principles

1. **No more broad jurisdictions before pilots.** Add depth and validation, not breadth.
2. **No unvalidated compliance claims.** Coverage and validation status must be visible in every report.
3. **Gate before dashboard.** CI/MCP/PR workflow matters more than web UI.
4. **PR-diff before full-repo perfection.** Agents ship changes, so assess changes.
5. **High-confidence blocking only.** Everything else is advisory or needs review.
6. **Design partners create the moat.** Real false-positive data matters more than more static rules.

---

## Phase 0 — Immediate stop/go validation sprint

**Timebox:** 7 days  
**Goal:** Decide whether customers want a privacy deploy gate.

### Work

- Fix public commands in README and docs.
- Add a simple CI workflow in this repo showing Clearway as a gate.
- Build one demo PR that fails then passes.
- Contact 50 targeted companies/founders/security leads.
- Offer local shadow-mode scans.
- Log every call and objection.

### Acceptance criteria

- 10 calls booked or completed.
- 3 companies agree to run a scan or see a live repo demo.
- At least 1 agrees to a two-week pilot or gives a strong “we need this” signal.

### Kill/pivot signal

- Fewer than 5 calls from 50 targeted messages.
- Nobody wants this in CI or MCP.
- All interest is “send me a report,” not “gate my agent PRs.”

---

## Phase 1 — Product narrative and docs reset

**Timebox:** 1–2 days  
**Goal:** Make the repo tell one clear international story.

### Work

- Replace README with agent privacy deploy gate framing.
- Replace YC application doc with international agent-gate narrative.
- Replace International Strategy with jurisdiction-pack runtime strategy.
- Replace Roadmap with this validation-first plan.
- Update Pricing to protected repo/pipeline model.
- Update INDEX and archive old debate/RFS docs.

### Acceptance criteria

- A new reader understands in 60 seconds:
  - who Clearway is for,
  - what action it gates,
  - why agents make this urgent,
  - what jurisdictions are supported,
  - what is validated vs early.

---

## Phase 2 — Real deploy-gate artifact

**Timebox:** 2–3 days  
**Goal:** Make “deploy gate” undeniable.

### Work

- Add `.github/workflows/clearway-gate.yml` to this repo.
- Add `examples/github-action/` with a copy-paste workflow.
- Add demo fixture repo or `demo/agent-pr-privacy-risk/`.
- Add `docs/DEMO-SCRIPT.md` for YC/demo calls.
- Ensure SARIF output works even when the scan fails.
- Ensure failure threshold is independent from SARIF severity.

### Acceptance criteria

- Demo PR fails on a known high-confidence privacy/security issue.
- After remediation, the same PR passes.
- SARIF is uploaded or generated.
- Agent-format JSON is compact and suitable for MCP clients.

---

## Phase 3 — Pack trust and coverage boundaries

**Timebox:** 3–5 days  
**Goal:** International without overclaiming.

### Work

Add metadata to each jurisdiction pack:

```ts
coverage: {
  summary: string;
  includedPrinciples: string[];
  excludedPrinciples: string[];
  knownGaps: string[];
  evidenceTypes: string[];
}
validation: {
  status: 'draft' | 'internal_validated' | 'external_reviewed' | 'customer_validated' | 'legal_partner_validated';
  reviewedBy?: string;
  reviewedAt?: string;
  notes?: string[];
}
```

Update report/opinion behavior:

- Unvalidated packs cannot emit broad `COMPLIANT` conclusions.
- Reports must show pack validation status and coverage boundaries.
- `BLOCK` should be allowed only for high-confidence deterministic checks.
- `NEEDS_REVIEW` should be the default for legal/contextual obligations.

### Acceptance criteria

- Each pack has visible coverage boundaries.
- Reports show validation status.
- CCPA/GDPR subset packs do not imply full compliance.
- Tests prove unvalidated packs cannot emit overbroad compliant verdicts.

---

## Phase 4 — PR-diff and agent metadata mode

**Timebox:** 1 week  
**Goal:** Make the product agent-native rather than scanner-native.

### Work

Add a PR/diff mode:

```bash
attestlens audit --diff-base origin/main --diff-head HEAD --jurisdiction eu-gdpr --format agent
```

Capture metadata:

- commit SHA,
- PR number if available,
- changed files,
- added routes/endpoints,
- added dependencies,
- added environment variables,
- agent/coding-tool hints if available,
- author/committer type.

Output should answer:

> “What privacy-relevant thing changed in this PR?”

Not just:

> “What issues exist in this repo?”

### Acceptance criteria

- Reports include changed-files summary.
- Findings can be marked `introducedInDiff: true`.
- Agent output prioritizes newly introduced issues.
- CI can run diff mode on pull requests.

---

## Phase 5 — Evidence graph lite

**Timebox:** 1–2 weeks  
**Goal:** Build moat without pretending to be a full GRC tool.

### Work

Create a lightweight evidence model:

```ts
Claim -> Evidence -> Control -> Jurisdiction -> Verdict
```

Examples:

- Claim: “This PR introduces a new data collection route.”
- Evidence: changed route file + request body schema + log statement.
- Control: GDPR Art. 13 transparency, Art. 6 lawful basis, APP 5 notification.
- Verdict: needs review.

Store evidence locally in reports first. Do not build a hosted brain yet.

### Acceptance criteria

- Each opinion can show evidence chain.
- Human reviewer can see exactly why the gate warned/blocked.
- Repeated scans can compare previous evidence to new evidence.

---

## Phase 6 — Taint-lite / data-flow minimum viable depth

**Timebox:** 2–4 weeks, only after pilots  
**Goal:** Close the biggest technical gap without trying to rebuild HoundDog.

### Work

Do not build full taint tracking immediately. Start with “taint-lite”:

- detect PII-like fields in schemas/forms/routes,
- detect sinks: logs, analytics SDKs, external HTTP calls, DB writes, LLM prompts,
- connect source file to sink file when obvious,
- produce route-level data-flow summaries.

### Acceptance criteria

- Detect PII source to log sink in common Node/Next/Express code.
- Detect PII source to analytics/tracker sink.
- Detect PII source to LLM prompt sink.
- Keep confidence explicit; uncertain flows are `NEEDS_REVIEW`.

---

## Phase 7 — Hosted/private evidence retention

**Timebox:** after paid pilots  
**Goal:** Monetize Pro/Enterprise.

### Work

- Local reports first.
- Optional hosted evidence retention later.
- Team policy settings.
- Suppression workflow.
- Approval records.
- Trend dashboard.

Do not build this before customer pull.

---

## Phase 8 — Jurisdiction-pack factory

**Timebox:** after customer validation  
**Goal:** Turn international expansion into moat.

### Work

- Improve AI-assisted rule drafting.
- Require human validation for blocking rules.
- Add pack tests and fixtures.
- Publish pack manifest format.
- Add pack changelog and validation status.
- Consider community or partner-contributed packs.

### Acceptance criteria

- A new jurisdiction pack can be drafted, tested, reviewed, and loaded without touching runtime code.
- Pack quality is measurable by tests, validation state, and customer false-positive data.

---

## 90-day outcome target

By 90 days, Clearway should have:

- 3–5 design partners.
- 1–2 paid pilots.
- A working CI gate in real repos.
- Measured false-positive rate.
- A demo-quality PR-diff workflow.
- Pack coverage/validation metadata.
- One customer quote about agent PR risk.

Without this, more features are likely waste.
