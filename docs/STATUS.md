# AttestLens — Status

**Last Updated:** 2026-04-29
**Product:** AI compliance service for the Privacy Act era. Agent-native. Opinion-grade. Always-on.
**North Star:** `docs/YC-RFS-EVOLUTION.md` — Three-Layer Product Thesis

---

## Current Focus

**Building Layer 2: Compliance Service** — transforming scanner output into opinion-grade, OAIC-ready compliance assessments.

See `docs/YC-RFS-EVOLUTION.md` for the full product thesis and `ATTESTLENS-EXECUTION-PLAN.md` (workspace root) for the phased build plan.

---

## Three-Layer Architecture

| Layer | Status | What |
|-------|--------|------|
| **1: Agent Infrastructure** | ✅ Shipped | MCP server (4 tools), CLI, structured JSON, fixPrompt, continuous monitoring |
| **2: Compliance Service** | 🔨 Next | Opinion-grade assessments, agent-native enhancements, reform module, SMB tier |
| **3: Compliance Brain** | 🔮 Defer | Emerges from monitoring data — don't build separately |

---

## Baseline (main, commit 61c15bc)

- 367 tests passing, `tsc --noEmit` clean
- 25,272 lines of TS across 70 source files
- CLI: scan, audit, report, attest, monitor
- MCP server: attestlens_scan, attestlens_scan_url, attestlens_audit, attestlens_map, attestlens_opinion
- Continuous monitoring: webhook receiver, baselines, regression detection, job queue, reporter
- All M3 scanner enhancements shipped (OSV, provenance, confidence, timeouts, behavioral, gitleaks, SAST-lite, IaC, dedup, maturity)

---

## Build Plan (Layer 2)

| Phase | Branch | Est. | Status |
|-------|--------|------|--------|
| 1: Opinion-Grade Assessments | `feature/opinion-grade-assessments` | 3-4 days | ✅ Done (commit 147da44) |
| 2: Agent-Native Enhancements | `feature/agent-native` | 2-3 days | 🔨 Next |
| 3: Privacy Act 2026 Reform Module | `feature/reform-module` | 3-4 days | ⏳ Blocked on 2 |
| 4: SMB Compliance Tier | `feature/smb-tier` | 3-4 days | ⏳ Blocked on 3 |
| 5: Integration + Sellable Gate | `feature/sellable-gate` | 2 days | ⏳ Blocked on 4 |

Each phase: own branch → merge to main → next phase. 367+ tests must pass after every merge.

---

## What's Shipped (Full History)

### Phase 1 — Opinion-Grade Assessments ✅
- `ComplianceOpinion` schema: verdict, confidence, per-principle opinions, evidence chains
- Deterministic opinion engine (`buildComplianceOpinion`) — no LLM calls
- CLI `--opinion` flag with color-coded verdict display
- HTML + Markdown opinion sections (color-coded badges, per-principle table, signature)
- MCP `attestlens_opinion` tool + `opinion` option on `attestlens_audit`
- 10 new tests (367 total)

### M3 — Scanner Enhancement ✅
- OSV.dev vulnerability integration (`--external-enrichment`)
- Dependency provenance detection (VS-SC-009)
- Dynamic confidence scoring
- Per-adapter timeout + progress reporting
- Behavioral supply-chain analysis (6 signals)
- Git history secret scanning via gitleaks
- SAST-lite compliance-critical patterns (20 rules)
- IaC misconfiguration: Dockerfile + Terraform
- Cross-scanner finding deduplication with `corroboratedBy`
- Package maturity scoring (VS-SC-010)

### M2.5 — Rule Freshness Foundation ✅
- Typed rule-pack manifest and freshness metadata
- Embedded rule pack, cache loader, corrupt-cache fallback
- `attestlens update-rules` command
- Opt-in `--auto-update` with bounded loading

### M2 — Compliance Moat ✅
- Interactive APP/NDB questionnaire with branching, frozen per-session question sets, resume
- Assessment-basis modes: artifact_only, codebase_only, operator_attested
- Merged scan + questionnaire reporting (HTML, JSON, MD, PDF)
- Breach-readiness scoring and consultant-facing narrative sections
- Attestation validation workflow with scenarios, runbook, and review log

### M1.5 — Scanner Credibility ✅
- URL scanner with SSRF hardening
- Stack-specific repo checks (Supabase, Firebase, Stripe, Clerk/Auth0)
- PDF report generation
- Validation corpus runner (9 public targets)

### M1 — Core ✅
- Unified finding schema (Zod)
- Scanner adapters: GuardVibe fallback, MCP config, supply-chain, URL
- Scanner orchestrator (parallel, dedup)
- APP/NDB mapping engine (25 rules)
- CLI: scan, audit, report
- MCP server: 4 tools
- HTML, JSON, Markdown reporting

---

## Open Issues (from Code Review + Security Audit)

| ID | Severity | Description | Status |
|----|----------|-------------|--------|
| I-01 | Important | `any` types in MCP server arguments | Open |
| I-02 | Low | `any` types in CLI Commander options | Open |
| I-03 | Low | npm audit requires node_modules | Mitigated (checks + skips) |
| I-04 | Medium | Lockfile FP on shallow clones | Open |
| — | Low | No .gitignore respect in file walker | Open |
| — | Low | No retry/backoff for scanner failures | Open |

These are low priority vs. Layer 2 build. Address opportunistically.

---

## Risks

- **July 2026 deadline:** Privacy Act reforms create urgency but also a market window
- **Validation risk:** No design-partner feedback yet on report shape
- **Overbuild risk:** Dashboard/SaaS still deferred until Layer 2 proves value
- **Compliance credibility:** APP/NDB mapping must stay conservative where automation is weak

---

## Execution Rules

1. One phase at a time — no parallel branches
2. Merge to main between phases — keep main always deployable
3. 367+ tests must pass + tsc clean — no exceptions
4. Codex implements, Ada orchestrates and reviews
5. Opinion engine is deterministic — no LLM calls, fully reproducible
6. If Codex breaks tests — fix before merge, don't proceed