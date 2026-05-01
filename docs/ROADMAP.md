# Clearway by AttestLens — Roadmap

**Last Updated:** 2026-05-01
**Positioning:** The deploy gate for AI privacy risk. Multi-jurisdiction. Opinion-grade. Agent-native.
**North Star:** `docs/YC-RFS-EVOLUTION.md`

---

## Current Focus

**Phase 10-lite: Schema Decoupling** — Minimum changes to prove a new jurisdiction pack flows end-to-end without touching AU schema types.

All phases 1-9 shipped. Baseline: 504 tests passing, tsc clean, 8 MCP tools, 3 jurisdiction packs.

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
| Continuous Monitoring | Webhook receiver, baselines, regression detection, job queue, reporter | Apr 2026 |
| Phase 1 | Opinion-grade assessments and deterministic compliance opinions | Apr 2026 |
| Phase 2 | Agent-native output mode, single-principle checks, CI integration | Apr 2026 |
| Phase 3 | Privacy Act reform module and remediation suggestions | Apr 2026 |
| Phase 4 | SMB compliance tier and compliance-check workflow | Apr 2026 |
| Phase 5A | MCP protocol hardening and security audit fixes | Apr 2026 |
| Phase 5 | Sellable gate: README, v0.3.0 positioning, changelog, pricing | Apr 2026 |
| Phase 6 | Jurisdiction abstraction and pack manifest v2 | Apr 2026 |
| Phase 7 | US CCPA/CPRA jurisdiction pack | Apr 2026 |
| Phase 8 | EU GDPR subset jurisdiction pack and multi-jurisdiction report generator | Apr 2026 |
| Phase 9 | YC App Prep — demo, design partner strategy, application essay | Apr 2026 |

---

## Upcoming Phases

### Phase 10-lite: Schema Decoupling (3-5 days)
**Goal:** Prove a new jurisdiction pack flows end-to-end without touching AU schema types.

- Add `RegulationMapping` as primary path alongside `APPMapping` (backward compat)
- Add `RegulationPrinciple` + `PrincipleRegistry` for jurisdiction-aware lookups
- Add `regulationMappings` on findings, `regulationPrinciple` on questions (parallel fields)
- Flip `appMappings` required → optional; `regulationMappings` optional → required
- Fix `validatePrinciple()` to be jurisdiction-aware via `PrincipleRegistry`
- **Design doc:** `docs/PHASE-10-GLOBAL-SCHEMA-DECOUPLING.md`

### Phase 10.5: GitHub Action + MCP Recipes (1-2 days)
**Goal:** Ship the "deploy gate" story with actual artifacts.

- Copy-paste GitHub Action YAML for CI integration
- MCP setup recipes for Cursor, Claude Code, Codex
- Agent policy examples ("run clearway check before merge")
- Local preflight command docs for agent workflows

### Phase 11: Rule Authoring Pipeline (1-2 weeks)
**Goal:** Ship "law-to-blocked-build" demo — legal text → cited rules + tests + mappings → human approves → blocks a build.

- AI-assisted rule creation from legislation text (offline only)
- Human validation step before rules enter packs
- Runtime stays deterministic (zero LLM)
- **Design doc:** `docs/RULE-AUTHORING-PIPELINE.md`

### Phase 12: Post-MVP Enhancements (after design partner feedback)
- PII taint tracking (biggest technical gap vs. HoundDog)
- Shadow AI detection
- IDE plugins (VS Code, Cursor, IntelliJ)
- Confidence/false-positive classification on findings
- Docker image
- Standalone binary distribution

---

## Launch Sequence

1. **Phase 10-lite** → npm v0.4.0-beta publish (proves distribution)
2. **Design partner pilots** → 6-8 weeks, AU mid-market
3. **Phase 10.5** → CI deploy gate artifacts for pilots
4. **Phase 11** → Rule authoring demo (differentiation)
5. **v0.5/0.6** → Iterate on pilot feedback
6. **v1.0** → Only after stable schemas + live CI deployments + 3 design partners

---

## Jurisdiction Packs

| Jurisdiction | Status | Principles | Scanner Rules | Questionnaire |
|---|---|---|---|---|
| 🇦🇺 au-privacy-act | ✅ Live | 13 APP + NDB | 68 rules | 64 questions |
| 🇺🇸 us-ccpa | ✅ Live | 12 CCPA principles | 6 rules | 14 questions |
| 🇪🇺 eu-gdpr | ✅ Live | 14 GDPR principles | 6 rules | 20 questions |
| Next | ⏳ After validation | Pick from design-partner demand | | |

Expansion rule: add jurisdictions only when a buyer, design partner, or launch narrative needs them.

---

## The July 2026 Window

| Date | What |
|------|------|
| 1 Jul 2026 | 100K+ SMBs fall under Privacy Act (AML/CTF reforms) — **VERIFY THIS CLAIM** |
| 10 Dec 2026 | Automated decision-making transparency requirements |
| 10 Dec 2026 | Children's Online Privacy Code obligations |

⚠️ The "100K businesses" claim needs verification before using in YC pitch. Research in progress.

---

## Revenue Model

Matches `docs/PRICING.md`. Updated per GTM debate consensus.

| Tier | Price | What | Layer |
|-------|-------|------|-------|
| Free | $0 | CLI + MCP, 1 private repo, core packs, basic reports | Layer 1 |
| Pro | $99-199/mo per 5 repos | Unlimited scans, CI gating, opinions, evidence retention, alerts | Layer 2 |
| Enterprise | $15-50K+/yr | SSO, self-hosted, custom packs, integrations, named support | Layer 2+ |