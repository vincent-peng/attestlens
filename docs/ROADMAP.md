# AttestLens — Roadmap

**Last Updated:** 2026-04-29
**Positioning:** AI compliance service for the Privacy Act era. Agent-native. Opinion-grade. Always-on.
**North Star:** `docs/YC-RFS-EVOLUTION.md`

---

## Three Layers

```
Layer 3: Compliance Brain        🔮 Defer — emerges from monitoring data
Layer 2: Compliance Service       🔨 Building — opinion-grade + agent-native + reform + SMB
Layer 1: Agent Infrastructure     ✅ Shipped — MCP, CLI, structured output, monitoring
```

---

## Shipped Milestones

| Milestone | What | Date |
|-----------|------|------|
| M1 | Core schema, scanner adapters, orchestrator, APP/NDB mapping, CLI, MCP server | Apr 2026 |
| M1.5 | URL scanner, SSRF hardening, stack-specific checks, PDF reports, validation corpus | Apr 2026 |
| M2 | Questionnaire engine, assessment-basis modes, merged reports, breach readiness, consultant narratives | Apr 2026 |
| M2.5 | Rule freshness: typed manifests, embedded rules, cache fallback, update command | Apr 2026 |
| M3 | OSV integration, provenance, dynamic confidence, timeouts, behavioral analysis, gitleaks, SAST-lite, IaC, dedup, maturity | Apr 2026 |
| Continuous Monitoring | Webhook receiver, baselines, regression detection, job queue, checkout worker, reporter | Apr 2026 |

**Current:** 357 tests, tsc clean, 25,272 lines of TS.

---

## Layer 2 Build Plan

See `ATTESTLENS-EXECUTION-PLAN.md` (workspace root) for detailed implementation steps.

| Phase | Goal | Est. | Key Deliverables |
|-------|------|------|-----------------|
| 1 | Opinion-Grade Assessments | 3-4d | `ComplianceOpinion` schema, opinion engine (deterministic), CLI `--opinion`, MCP `attestlens_opinion`, report sections |
| 2 | Agent-Native Enhancements | 2-3d | Agent output format, `attestlens_check` MCP tool, streaming results, CI/CD GitHub Action |
| 3 | Privacy Act 2026 Reform Module | 3-4d | Reform scanner (4 provisions), `--reform` CLI flag, reform report section, `attestlens_reform` MCP tool |
| 4 | SMB Compliance Tier | 3-4d | `attestlens compliance-check`, SMB questionnaire (~15 plain-English questions), jargon-free report |
| 5 | Integration + Sellable Gate | 2d | README rewrite, v0.3.0 bump, changelog, full integration test, pricing content |

---

## Layer 3 (Deferred — Compliance Brain)

Don't build separately. It emerges from accumulated monitoring data:
- Compliance trend analysis (getting better or worse?)
- Predictive risk (which APP principles will regress?)
- Queryable compliance state API
- Agent-native querying ("am I still compliant after this change?")

Grows from monitoring subscriptions. Data accumulates, brain emerges.

---

## Post-Layer 2 (Not Scheduled)

- Web dashboard (M4) — only after design-partner validation of Layer 2
- AI-guided attestation — LLM-powered question branching, evidence extraction
- Billing/SaaS infrastructure
- Advisory monitoring rule update pipeline (Phase 3.5 from old roadmap)

---

## Revenue Model

| Tier | Price | What | Layer |
|-------|-------|------|-------|
| Free | $0 | CLI, MCP server, local scans, JSON | Layer 1 |
| Pro | $15 AUD/mo | Opinion-grade output, PDF, fixPrompt, 50 scans/mo | Layer 2 |
| Consultant | $49 AUD/mo | Continuous monitoring, white-label, unlimited, compliance opinions | Layer 2 |
| Enterprise | Custom | Compliance Brain API, SSO, SLA, self-hosted | Layer 3 |

---

## The July 2026 Window

| Date | What |
|------|------|
| 1 Jul 2026 | 100K+ SMBs fall under Privacy Act (AML/CTF reforms) |
| 10 Dec 2026 | Automated decision-making transparency requirements |
| 10 Dec 2026 | Children's Online Privacy Code obligations |

~3 month window (Jul–Sep 2026) where businesses scramble. Opinion-grade assessments + reform module = the product for this window.