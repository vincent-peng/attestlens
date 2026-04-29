# AttestLens × YC Summer 2026 RFS — Product Thesis

**Date:** 2026-04-29  
**Source:** YC Summer 2026 RFS — "AI has stopped being a feature and started being the foundation."

---

## Three RFS Categories Map Directly to AttestLens

### 1. AI-Native Service Companies (Gustaf Alströmer)
> "Don't sell software — sell the service. Instead of giving you a tool, they just do the work."
> Specifically lists: **Compliance**

**AttestLens today:** A scanner that finds problems and generates reports. The human still has to read the report, interpret the findings, and decide what to do.

**AttestLens tomorrow:** An AI compliance service that delivers the finished assessment — opinion-grade, evidence-backed, signed by AttestLens. The human reviews it, not writes it.

**The shift:** Scanner → "Here are 47 findings mapped to APP principles" vs Service → "**NOT COMPLIANT.** APP 11 (Cross-border disclosure) is NOT MET. Immediate remediation required. Evidence: 3 high-severity findings, 2 corroborated. Confidence: HIGH. Signed: AttestLens v0.3.0, 2026-04-29T10:00:00Z."

**What to build:** Compliance opinion layer (`ComplianceOpinion`) that produces definitive verdicts (COMPLIANT / PARTIALLY_COMPLIANT / NON_COMPLIANT) per APP principle with evidence chains, confidence levels, and formal attestation metadata. The data already exists in our APP controls and breach readiness — this is a presentation layer, not a new engine.

---

### 2. Software for Agents (Aaron Epstein) 🆕
> "The next trillion users on the internet won't be people. They'll be AI agents. Every major category of software needs to be rebuilt for agents as first-class citizens, and that won't come from incumbents."

**AttestLens today:** Already ships as an MCP server with 4 tools (`attestlens_scan`, `attestlens_scan_url`, `attestlens_audit`, `attestlens_map`). Any coding agent can call it mid-build.

**The opportunity:** Compliance checking is the *perfect* agent-native function because:
- It's **stateless** — scan, return structured data, done
- It's **high-frequency** — every `npm install`, every `git push`, every PR
- It's **cross-cutting** — every codebase needs it, no one wants to think about it
- The **output is machine-readable** — APP principle status, confidence scores, findings with `fixPrompt` — all structured, all consumable by agents

**What exists:** MCP server with stdio transport, 4 tools, structured JSON output, `fixPrompt` on every finding.

**What to add:**
- **Agent-native output mode** — machine-first, not human-first. Skip the narrative, return structured verdict + actions
- **`attestlens_check`** — lightweight, fast, single-principle check ("am I APP 11 compliant?")
- **CI/CD agent hooks** — GitHub Action that runs on push/PR, posts results as check status
- **Streaming results** — agents don't want to wait 30s for a full audit. Return findings as they arrive.

This is the easiest RFS win because the infrastructure exists. We're not building from zero — we're surfacing what's already there in an agent-first way.

---

### 3. Company Brain (Tom Blomfield)
> "A system that pulls knowledge out of fragmented sources, structures it, keeps it current, and turns it into an executable skills file for AI."

**AttestLens today:** Each scan is point-in-time. No memory between scans.

**AttestLens tomorrow:** Continuous monitoring creates a **Compliance Brain** — a persistent, queryable model of a company's compliance posture. "What's our APP 8 status?" → instant answer with evidence chain.

**What exists:** Continuous monitoring (Phase 1) — webhook receiver, baseline storage, regression detection, job queue, checkout worker, PR comments, Slack/Discord notifications. 1,446 lines, merged to main.

**What emerges:** With accumulated scan data over time:
- Compliance trend analysis (are we getting better or worse?)
- Predictive risk (which APP principles are most likely to regress?)
- Queryable compliance state (API for "current status of APP_11")
- Agent-native querying ("am I still compliant after this change?")

**Don't build this separately.** It grows from the monitoring subscription. The data accumulates, the brain emerges.

---

## Product Thesis: The Three Layers

AttestLens is positioned at the intersection of three YC RFS categories. That's not a coincidence — it's the product thesis:

```
┌─────────────────────────────────────────────┐
│  Layer 3: Company Brain (deferred)          │
│  Persistent, queryable compliance model     │
│  Emerges from monitoring data over time     │
├─────────────────────────────────────────────┤
│  Layer 2: Compliance Service (opinion-grade) │
│  "Here's your compliance opinion, signed"   │
│  Transforms scanner → service               │
├─────────────────────────────────────────────┤
│  Layer 1: Agent Infrastructure (shipped)    │
│  MCP server, CLI, structured output          │
│  Agents as first-class citizens             │
└─────────────────────────────────────────────┘
```

Layer 1 is done. Layer 2 is the next build. Layer 3 is the long game.

---

## Sharpened Positioning

**Before:** "AI-Powered Australian Privacy Act Compliance Scanner"

**After:** "AI compliance service for the Privacy Act era. Agent-native. Opinion-grade. Always-on."

The reframe:
- **Scanner** → **Service** (AI-Native Service Companies)
- **Reports** → **Opinions** (AI-Native Service Companies)
- **CLI tool** → **Agent infrastructure** (Software for Agents)
- **Point-in-time** → **Always-on brain** (Company Brain)

---

## Priority: What to Build Next

### ✅ Layer 1: Agent Infrastructure — SHIPPED
- MCP server (4 tools, stdio transport)
- CLI (scan, audit, report, monitor, attest)
- Structured JSON output with `fixPrompt`
- Continuous monitoring (webhook, baselines, regression)
- 357 tests passing, 25,272 lines of TS

### 🔨 Layer 2: Compliance Service — NEXT BUILD
Two parallel tracks:

**Track A: Opinion-Grade Assessments** (product shift, ~3-4 days)
- `ComplianceOpinion` schema type — verdict, confidence, evidence chain, attestation metadata
- Opinion engine — deterministic verdict from existing APP control data
- Agent-native output mode — machine-first structured verdict
- CLI `--opinion` flag + MCP tool `attestlens_opinion`
- Report sections (HTML/MD) for the opinion
- Tests + tsc clean

**Track B: Agent-Native Enhancements** (shipping polish, ~2-3 days)
- `attestlens_check` MCP tool — lightweight single-principle check
- Agent output mode — skip narrative, return verdict + actions
- Streaming results — return findings as they arrive, not after full scan
- CI/CD integration guide — GitHub Action template

### 🔮 Layer 3: Compliance Brain — DEFER
- Queryable compliance state API
- Trend analysis from accumulated baselines
- Predictive risk scoring
- Agent-native querying ("am I still compliant after this change?")
- Let this grow from monitoring subscriptions, don't build separately

---

## The July 2026 Window

The Privacy Act reforms create a hard deadline that gives Layer 2 urgency:

- **1 July 2026:** 100K+ SMBs fall under Privacy Act (AML/CTF reforms)
- **10 December 2026:** Automated decision-making transparency requirements
- **10 December 2026:** Children's Online Privacy Code obligations

~3 month window (July–September 2026) where businesses scramble to understand new obligations.

**Opinion-grade assessments are the product for this window.** "Is my code compliant with the new Privacy Act?" → definitive answer, not "here are some findings to interpret."

**Agent-native compliance is the moat for after.** Every coding agent runs AttestLens on every build. That's the compounding advantage.

---

## Revenue Model (Aligned with Three Layers)

| Tier | Price | What | Who |
|---|---|---|---|
| **Free** | $0 | CLI, MCP server, local scans, JSON output | Indie devs, agents |
| **Pro** | $15 AUD/mo | Opinion-grade output, PDF reports, `fixPrompt`, 50 scans/mo | Solo devs, small teams |
| **Consultant** | $49 AUD/mo | Continuous monitoring, white-label reports, unlimited scans, compliance opinions | AU consultants, MSPs |
| **Enterprise** | Custom | Compliance Brain API, SSO, SLA, self-hosted | Large orgs, government |

Free tier = Layer 1 (agent infrastructure). Pro/Consultant = Layer 2 (compliance service). Enterprise = Layer 3 (compliance brain).

---

## What This Replaces

This doc supersedes:
- ❌ SELLABLE-TODOS.md (pre-YC research, deleted)
- ❌ ATTESTLENS-EXECUTION-PLAN.md (pre-YC research, deleted)

The sellable todos were feature lists. This is a product thesis grounded in YC's stated investment thesis for Summer 2026.