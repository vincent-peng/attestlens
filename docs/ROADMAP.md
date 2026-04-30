# Clearway by AttestLens — Roadmap

**Last Updated:** 2026-04-30
**Positioning:** Deterministic compliance runtime for AI agents. Multi-jurisdiction. Opinion-grade. Agent-native.
**North Star:** `docs/YC-RFS-EVOLUTION.md`

---

## Current Focus

**Phase 9: YC App Prep** — multi-jurisdiction demo, design partner outreach, and application essay.

All Layer 2 phases are shipped. Current baseline is 502 tests passing with `tsc --noEmit` clean, 8 MCP tools, and 3 jurisdiction packs live.

---

## Three Layers

```
Layer 3: Compliance Brain        🔮 Defer — emerges from monitoring data
Layer 2: Compliance Service      ✅ Shipped — opinion-grade + agent-native + reform + SMB + multi-jurisdiction
Layer 1: Agent Infrastructure    ✅ Shipped — MCP, CLI, structured output, monitoring
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
| Phase 1 | Opinion-grade assessments and deterministic compliance opinions | Apr 2026 |
| Phase 2 | Agent-native output mode, single-principle checks, CI integration | Apr 2026 |
| Phase 3 | Privacy Act reform module and remediation suggestions | Apr 2026 |
| Phase 4 | SMB compliance tier and compliance-check workflow | Apr 2026 |
| Phase 5A | MCP protocol hardening and security audit fixes | Apr 2026 |
| Phase 5 | Sellable gate: README, v0.3.0 positioning, changelog, pricing | Apr 2026 |
| Phase 6 | Jurisdiction abstraction and pack manifest v2 | Apr 2026 |
| Phase 7 | US CCPA/CPRA jurisdiction pack | Apr 2026 |
| Phase 8 | EU GDPR subset jurisdiction pack and multi-jurisdiction report generator | Apr 2026 |

---

## Current Baseline

- 502 tests passing, `tsc --noEmit` clean
- CLI: scan, audit, report, attest, monitor, compliance-check + agent format + opinion
- MCP server: 8 tools (scan, scan_url, audit, map, opinion, check, compliance_check, reform)
- Jurisdiction packs: au-privacy-act, us-ccpa, eu-gdpr
- Multi-jurisdiction report generator with AU, US, and EU sections
- Continuous monitoring: webhook receiver, baselines, regression detection, job queue, reporter
- MCP hardening: McpServer, Zod schemas, structuredContent, fail-closed filesystem, DNS pinning, TOCTOU revalidation, opaque resource URIs, error sanitization, AbortSignal cancellation

---

## Layer 2 Build Plan

| Phase | Goal | Key Deliverables | Status |
|-------|------|------------------|--------|
| 1 | Opinion-Grade Assessments | `ComplianceOpinion` schema, opinion engine, CLI `--opinion`, MCP `attestlens_opinion`, report sections | ✅ Done |
| 2 | Agent-Native Enhancements | Agent output format, `attestlens_check` MCP tool, CI/CD integration guide | ✅ Done |
| 3 | Privacy Act 2026 Reform Module | Reform scanner, remediation suggestions, reform report section, `attestlens_reform` MCP tool | ✅ Done |
| 4 | SMB Compliance Tier | `attestlens compliance-check`, SMB questionnaire, jargon-free report | ✅ Done |
| 5A | MCP Hardening + Security Audit | McpServer migration, Zod schemas, structuredContent, fail-closed filesystem, URL/path hardening | ✅ Done |
| 5 | Integration + Sellable Gate | README rewrite, v0.3.0 bump, changelog, pricing content, full integration test | ✅ Done |
| 6 | Jurisdiction Abstraction | Jurisdiction schemas, pack manifest v2, `--jurisdiction` across CLI and MCP tools | ✅ Done |
| 7 | US CCPA/CPRA Pack | CCPA principles, mapping rules, scanner rules, questionnaire, embedded pack | ✅ Done |
| 8 | EU GDPR Subset Pack | GDPR principles, mapping rules, scanner rules, questionnaire, multi-jurisdiction reports | ✅ Done |

---

## Phase 9: YC App Prep

- Multi-jurisdiction demo that shows AU + US + EU output from the same runtime
- Design partner outreach and feedback logging
- YC application essay and product narrative
- Conservative claims: "multi-jurisdiction" until the packs are externally validated

---

## Jurisdiction Expansion

| Jurisdiction | Status | Notes |
|---|---|---|
| 🇦🇺 au-privacy-act | ✅ Live | Proof jurisdiction with APP, NDB, reform, SMB workflow |
| 🇺🇸 us-ccpa | ✅ Live | Commercial wedge for US privacy buyers and YC network |
| 🇪🇺 eu-gdpr | ✅ Live | Credibility jurisdiction with scoped GDPR subset |
| Next | ⏳ After validation | Pick from design-partner demand, not roadmap speculation |

Expansion rule: add jurisdictions only when a buyer, design partner, or launch narrative needs them. Keep legal automation conservative where evidence is weak.

---

## Layer 3 (Deferred — Compliance Brain)

Don't build separately. It emerges from accumulated monitoring data:

- Compliance trend analysis
- Predictive risk by principle and jurisdiction
- Queryable compliance state API
- Agent-native querying: "am I still compliant after this change?"

---

## Revenue Model

Matches `docs/PRICING.md`.

| Tier | Price | What | Layer |
|-------|-------|------|-------|
| Free | $0 | Local scans, 3 core tools, basic project and URL assessment | Layer 1 |
| Pro | $29/mo | All 8 MCP tools, opinion engine, reform module, agent-native reports, SMB compliance-check | Layer 2 |
| Enterprise | Custom | Custom onboarding, team workflows, deployment/procurement support, custom reporting | Layer 2+ |

---

## The July 2026 Window

| Date | What |
|------|------|
| 1 Jul 2026 | 100K+ SMBs fall under Privacy Act (AML/CTF reforms) |
| 10 Dec 2026 | Automated decision-making transparency requirements |
| 10 Dec 2026 | Children's Online Privacy Code obligations |

The July to September 2026 window remains the AU urgency wedge. Multi-jurisdiction coverage broadens the demo and buyer relevance, but the product should avoid claiming global coverage until external validation supports it.
