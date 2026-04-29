# AttestLens Transformation — Execution Plan

**Orchestrator:** Ada  
**Implementer:** Codex (via acpx)  
**Date:** 2026-04-29  
**Source:** docs/YC-RFS-EVOLUTION.md — Three-Layer Product Thesis  

---

## Baseline

- Branch: `main` (commit 61c15bc)
- Tests: 357 passing, tsc clean
- Total: 25,272 lines of TS across 70 source files
- Key schema: `ComplianceReport` with `APPControl`, `BreachReadiness`, `ConsultantNarrative`
- Key infra: MCP server (4 tools), CLI (scan/audit/report/attest/monitor), continuous monitoring

---

## Phase Overview

```
Phase 1: Opinion-Grade Assessments     (3-4 days) ← NEXT
Phase 2: Agent-Native Enhancements     (2-3 days)
Phase 3: Privacy Act 2026 Reform Module (3-4 days)
Phase 4: SMB Compliance Tier            (3-4 days)
Phase 5: Integration + Sellable Gate    (2 days)
```

Each phase on its own branch. Merge to main between phases. 357 tests must pass + tsc clean after each merge.

---

## Phase 1: Opinion-Grade Assessments

**Branch:** `feature/opinion-grade-assessments`  
**Goal:** Transform scanner output → OAIC-ready compliance opinion  

### Why first
This is the biggest product shift with the least new code. The data already exists in `APPControl.status`, `APPControl.score`, `BreachReadiness`, and `ConsultantNarrative`. We're adding a presentation layer that produces definitive verdicts, not new scanning logic.

### Implementation Steps

**Step 1: Schema types** (src/schema/index.ts)
- Add `ComplianceVerdict` enum: `COMPLIANT | PARTIALLY_COMPLIANT | NON_COMPLIANT`
- Add `OpinionConfidence` enum: `HIGH | MODERATE | LOW`
- Add `PrincipleOpinion` type:
  ```
  principle: APPPrinciple
  verdict: ComplianceVerdict
  confidence: OpinionConfidence
  score: number (0-100, from APPControl)
  summary: string (deterministic from status + findings)
  evidenceCount: number
  corroboratedCount: number
  keyFindings: string[] (top 3 finding IDs by severity)
  ```
- Add `ComplianceOpinion` type:
  ```
  overallVerdict: ComplianceVerdict
  overallConfidence: OpinionConfidence
  signedBy: string ("AttestLens v0.3.0")
  signedAt: string (ISO datetime)
  principles: PrincipleOpinion[]
  riskLevel: from ComplianceReport.riskLevel
  score: number (from ComplianceReport.overallScore)
  disclaimer: string
  ```
- Add `complianceOpinion` optional field to `ComplianceReport`

**Step 2: Opinion engine** (src/opinion/engine.ts)
- `buildComplianceOpinion(report: ComplianceReport, options?: { strictMode?: boolean }): ComplianceOpinion`
- Deterministic logic:
  - Per-principle verdict: PASS→COMPLIANT, FAIL→NON_COMPLIANT, UNKNOWN→PARTIALLY_COMPLIANT (or NON_COMPLIANT in strict mode)
  - Confidence: based on evidence basis + corroborated findings count + finding severity distribution
  - Overall verdict: worst principle verdict wins (any NON_COMPLIANT → overall NON_COMPLIANT; all COMPLIANT → COMPLIANT; else PARTIALLY_COMPLIANT)
  - Overall confidence: minimum of principle confidences, weighted by risk
- No LLM calls — fully deterministic, auditable, reproducible

**Step 3: Report integration** (src/report/generator.ts)
- Add `includeOpinion` to `ReportOptions`
- Add `complianceOpinion` field to `buildComplianceReport` return
- Add HTML section: `generateHTMLComplianceOpinionSection(opinion)` — verdict badge (color-coded), per-principle table, confidence indicators, signature block
- Add Markdown section: similar but text-based
- Add JSON: opinion object in report output

**Step 4: CLI integration** (src/cli/index.ts)
- Add `--opinion` flag to `audit` command
- Wire `options.opinion` → `ReportOptions.includeOpinion`
- Display opinion verdict in terminal summary after audit

**Step 5: MCP integration** (src/mcp/index.ts)
- Add `attestlens_opinion` MCP tool
- Input: `path` + optional `strict` flag
- Output: `ComplianceOpinion` as structured JSON
- Add `opinion` boolean option to `attestlens_audit` tool

**Step 6: Tests** (src/opinion/engine.test.ts)
- Test verdict logic: all pass → COMPLIANT, any fail → NON_COMPLIANT, mixed → PARTIALLY_COMPLIANT
- Test strict mode: UNKNOWN → NON_COMPLIANT
- Test confidence calculation: evidence basis, corroboration, severity weighting
- Test overall verdict aggregation
- Test edge cases: empty findings, all unknown, single principle fail

### Acceptance Criteria
- [ ] `tsc --noEmit` clean
- [ ] All existing 357 tests pass
- [ ] New opinion engine tests pass (6+)
- [ ] `attestlens audit ./my-project --opinion` shows verdict in terminal
- [ ] HTML report includes opinion section when `--opinion` flag used
- [ ] MCP `attestlens_opinion` tool returns structured verdict
- [ ] Opinion is deterministic — same input → same output

---

## Phase 2: Agent-Native Enhancements

**Branch:** `feature/agent-native`  
**Goal:** Make AttestLens the default compliance tool for coding agents  

### Implementation Steps

**Step 1: Agent output mode** (src/report/generator.ts + src/mcp/index.ts)
- Add `agent` format to `ReportFormat` enum
- Agent output: `{ verdict, score, actions: [{ principle, verdict, action, fixPrompt }] }`
- Minimal, machine-first, no narrative
- MCP tools return agent format when `format: "agent"` is specified

**Step 2: `attestlens_check` MCP tool** (src/mcp/index.ts)
- Lightweight single-principle check
- Input: `path` + `principle` (e.g., "APP_11")
- Output: `{ principle, verdict, score, findings: [...] }`
- Fast — only runs relevant scanners for that principle

**Step 3: Streaming/progress for MCP** (src/mcp/index.ts)
- Send partial results via MCP progress notifications
- Return early findings before full scan completes
- Agents get results faster on large codebases

**Step 4: CI/CD integration** (docs/ci-integration.md + .github/workflows/attestlens.yml)
- GitHub Action template: runs on push/PR, posts check status
- Example workflow with opinion output as PR comment
- Document `ATTESTLENS_GITHUB_TOKEN` and webhook setup

### Acceptance Criteria
- [ ] `attestlens_audit` MCP tool supports `format: "agent"` 
- [ ] `attestlens_check` MCP tool works for single-principle queries
- [ ] CI/CD integration guide + example GitHub Action
- [ ] All 357+ tests pass, tsc clean

---

## Phase 3: Privacy Act 2026 Reform Module

**Branch:** `feature/reform-module`  
**Goal:** "Does your code comply with the July 2026 Privacy Act obligations?" — THE pitch  

### Implementation Steps

**Step 1: Reform schema** (src/schema/reform.ts)
- `ReformProvision` enum: `STATUTORY_TORT`, `CHILDREN_PRIVACY_CODE`, `AUTOMATED_DECISION_MAKING`, `AML_CTF`
- `ReformFinding` type: provision, severity, title, description, fixPrompt, effectiveDate
- `ReformImpactAssessment` type: overall impact, per-provision findings, compliance gaps, action items

**Step 2: Reform scanner** (src/scanner/reform.ts)
- Detect PII handling patterns relevant to each reform provision
- Detect AI/ML decision-making code (model loading, inference, scoring)
- Detect minor/children data handling (age gates, COPPA-like patterns)
- Detect cross-border data transfer patterns
- Map to reform provisions with effective dates

**Step 3: Reform report section** (src/report/generator.ts)
- "2026 Privacy Act Impact" section in HTML/MD/JSON
- Per-provision assessment: compliant / gap / unknown
- Timeline: what's due when (Jul 2026, Dec 2026)
- Priority actions ordered by effective date

**Step 4: CLI + MCP**
- `--reform` flag on audit command
- `attestlens_reform` MCP tool
- `reform-2026` scanner source in orchestrator

### Acceptance Criteria
- [ ] Reform scanner detects 4 provision categories
- [ ] CLI `--reform` flag works
- [ ] Report includes reform impact section
- [ ] 5+ new tests, all existing pass

---

## Phase 4: SMB Compliance Tier

**Branch:** `feature/smb-tier`  
**Goal:** Open the 100K+ SMB market — plain-English "am I compliant?"  

### Implementation Steps

**Step 1: Simplified CLI** (src/cli/index.ts)
- `attestlens compliance-check <target>` — guided, plain-English
- Checkbox questionnaire for SMBs (no jargon)
- Output: Compliance Readiness Score + plain-English gap report

**Step 2: SMB questionnaire** (src/questionnaire/smb.ts)
- Reduced question set (~15 questions vs full ~50)
- Plain-English: "Do you store customer names?" not "APP_3: Is collection lawful and necessary?"
- Auto-maps to APP principles internally

**Step 3: Plain-English report** (src/report/smb-generator.ts)
- No APP principle codes in output
- "You need to fix X" not "APP_11 is NON_COMPLIANT"
- Action-oriented: do this, by this date, because this law says so

### Acceptance Criteria
- [ ] `attestlens compliance-check` works end-to-end
- [ ] SMB questionnaire has ~15 plain-English questions
- [ ] Report is jargon-free, action-oriented
- [ ] All tests pass

---

## Phase 5: Integration + Sellable Gate

**Branch:** `feature/sellable-gate`  
**Goal:** Final polish before we can charge money  

### Steps
- README rewrite with three-layer positioning
- Version bump to 0.3.0
- Changelog for all phases
- Smoke test: full audit + opinion + reform + SMB on a real project
- Pricing page content (for website)
- npm package metadata update

### Acceptance Criteria
- [ ] README reflects new positioning
- [ ] `npm run build` + `npm publish --dry-run` works
- [ ] Full integration test: audit → opinion → reform → SMB on sample project
- [ ] All 360+ tests pass, tsc clean

---

## Delegation Rules

1. **One phase at a time** — no parallel phase branches
2. **Merge to main between phases** — keep main always deployable
3. **357 tests must pass + tsc clean** — no exceptions
4. **Codex does implementation** — Ada writes the prompt, reviews the output, merges
5. **Opinion engine is deterministic** — no LLM calls, fully reproducible
6. **Each Codex prompt** includes: exact files to modify, schema types to add, test requirements, acceptance criteria
7. **If Codex breaks tests** — fix before merge, don't proceed to next phase

---

## Current Status

- [ ] Phase 1: Opinion-Grade Assessments — READY TO START
- [ ] Phase 2: Agent-Native Enhancements — blocked on Phase 1
- [ ] Phase 3: Reform Module — blocked on Phase 2
- [ ] Phase 4: SMB Tier — blocked on Phase 3
- [ ] Phase 5: Integration Gate — blocked on Phase 4