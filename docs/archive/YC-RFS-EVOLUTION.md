# AttestLens × YC Summer 2026 RFS — Product Thesis

**Date:** 2026-04-30
**Source:** YC Summer 2026 RFS — "AI has stopped being a feature and started being the foundation."

---

## Three RFS Categories Map Directly to AttestLens

### 1. AI-Native Service Companies (Gustaf Alströmer)
> "Don't sell software — sell the service. Instead of giving you a tool, they just do the work."
> Specifically lists: **Compliance**

**AttestLens shipped:** An opinion-grade compliance runtime that turns scanner evidence, questionnaire evidence, and jurisdiction packs into signed deterministic assessments.

**The service shape:** "NOT COMPLIANT. APP 11 is not met. Immediate remediation required. Evidence: 3 high-severity findings, 2 corroborated. Confidence: HIGH. Signed: AttestLens v0.3.0."

**Why this matters:** The human reviews a finished compliance opinion instead of interpreting raw scanner findings.

---

### 2. Software for Agents (Aaron Epstein)
> "The next trillion users on the internet won't be people. They'll be AI agents. Every major category of software needs to be rebuilt for agents as first-class citizens, and that won't come from incumbents."

**AttestLens today:** Ships as an MCP server with 8 tools (`attestlens_scan`, `attestlens_scan_url`, `attestlens_audit`, `attestlens_map`, `attestlens_opinion`, `attestlens_check`, `attestlens_compliance_check`, `attestlens_reform`). Any coding agent can call it mid-build.

**The opportunity:** Compliance checking is the perfect agent-native function because:

- It's stateless — scan, return structured data, done
- It's high-frequency — every dependency change, PR, and release
- It's cross-cutting — every codebase needs it, few teams want to own it manually
- The output is machine-readable — verdicts, confidence, evidence, and `fixPrompt` values are structured

**What exists:** MCP server with stdio transport, 8 tools, structured JSON, structuredContent, Zod schemas, fail-closed path and URL handling, and agent-native output mode.

---

### 3. Company Brain (Tom Blomfield)
> "A system that pulls knowledge out of fragmented sources, structures it, keeps it current, and turns it into an executable skills file for AI."

**AttestLens today:** Continuous monitoring creates the substrate for a compliance brain: webhook receiver, baseline storage, regression detection, job queue, checkout worker, reports, and notifications.

**What emerges:** With accumulated scan and questionnaire data over time:

- Compliance trend analysis by principle and jurisdiction
- Predictive risk from repeated regressions
- Queryable compliance state
- Agent-native querying: "am I still compliant after this change?"

**Don't build this separately.** It grows from monitoring subscriptions. The data accumulates, the brain emerges.

---

## Product Thesis: The Three Layers

AttestLens is positioned at the intersection of three YC RFS categories:

```
┌─────────────────────────────────────────────┐
│  Layer 3: Company Brain (deferred)          │
│  Persistent, queryable compliance model     │
│  Emerges from monitoring data over time     │
├─────────────────────────────────────────────┤
│  Layer 2: Compliance Service (shipped)      │
│  Opinion-grade, multi-jurisdiction runtime  │
│  Transforms scanner → service               │
├─────────────────────────────────────────────┤
│  Layer 1: Agent Infrastructure (shipped)    │
│  MCP server, CLI, structured output          │
│  Agents as first-class citizens             │
└─────────────────────────────────────────────┘
```

Layer 1 and Layer 2 are shipped. Layer 3 is the long game.

---

## Multi-Jurisdiction Positioning

AttestLens is now multi-jurisdiction, not global. The current live packs are:

| Jurisdiction | Status | Scope |
|---|---|---|
| 🇦🇺 au-privacy-act | ✅ Live | APP + NDB, reform, SMB compliance |
| 🇺🇸 us-ccpa | ✅ Live | CCPA/CPRA subset for US privacy checks |
| 🇪🇺 eu-gdpr | ✅ Live | GDPR subset for AI/privacy evidence checks |

See `docs/INTERNATIONAL-STRATEGY.md` for the expansion strategy and boundaries.

---

## Sharpened Positioning

**Before:** "AI-Powered Australian Privacy Act Compliance Scanner"

**After:** "Deterministic compliance runtime for AI agents. Multi-jurisdiction. Opinion-grade. Agent-native."

The reframe:

- **Scanner** → **Service** (AI-Native Service Companies)
- **Reports** → **Opinions** (AI-Native Service Companies)
- **CLI tool** → **Agent infrastructure** (Software for Agents)
- **Point-in-time** → **Always-on brain** (Company Brain)
- **AU-only** → **Multi-jurisdiction** (AU + US CCPA + EU GDPR)

---

## Shipped State

### ✅ Layer 1: Agent Infrastructure

- MCP server (8 tools, stdio transport)
- CLI (scan, audit, report, monitor, attest, compliance-check)
- Structured JSON output with `fixPrompt`
- Agent-native report format
- Continuous monitoring (webhook, baselines, regression)
- 502 tests passing

### ✅ Layer 2: Compliance Service

- Deterministic `ComplianceOpinion` schema and opinion engine
- CLI `--opinion` flag and MCP `attestlens_opinion`
- Single-principle `attestlens_check`
- SMB compliance-check workflow
- Privacy Act reform module and `attestlens_reform`
- MCP hardening: McpServer, Zod schemas, structuredContent, fail-closed filesystem, DNS pinning, TOCTOU revalidation, opaque resource URIs, error sanitization, AbortSignal cancellation
- Jurisdiction abstraction and 3 live jurisdiction packs
- Multi-jurisdiction report generator

### 🔮 Layer 3: Compliance Brain — Defer

- Queryable compliance state API
- Trend analysis from accumulated baselines
- Predictive risk scoring
- Agent-native querying
- Let this grow from monitoring subscriptions; don't build separately

---

## Current Priority: Phase 9

**YC App Prep**

- Multi-jurisdiction demo
- Design partner outreach
- Application essay
- Conservative validation narrative: multi-jurisdiction coverage is live, but not yet externally validated as global coverage

---

## The July 2026 Window

The Privacy Act reforms create a hard deadline:

- **1 July 2026:** 100K+ SMBs fall under Privacy Act (AML/CTF reforms)
- **10 December 2026:** Automated decision-making transparency requirements
- **10 December 2026:** Children's Online Privacy Code obligations

Opinion-grade assessments are the AU wedge. Multi-jurisdiction packs make the product credible beyond Australia without claiming more than the current evidence supports.

---

## Revenue Model (Aligned with Current Pricing)

| Tier | Price | What | Who |
|---|---|---|---|
| **Free** | $0 | Local scans, 3 core tools, basic project and URL assessment | Indie devs, agents |
| **Pro** | $29/mo | All 8 MCP tools, opinion engine, reform module, agent-native reports, SMB compliance-check | Solo devs, small teams |
| **Enterprise** | Custom | Custom onboarding, team workflows, deployment/procurement support, custom reporting | Large orgs, regulated teams |

Free tier = Layer 1 adoption. Pro and Enterprise monetize Layer 2. Layer 3 remains deferred until monitoring data justifies it.

---

## What This Replaces

This doc supersedes older execution and sellable-todo plans. The product thesis is now grounded in shipped Layer 1 and Layer 2 capability plus the YC Summer 2026 RFS narrative.
