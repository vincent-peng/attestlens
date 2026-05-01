# Clearway by AttestLens — Status

**Last Updated:** 2026-05-01
**Positioning:** The deploy gate for AI privacy risk. Multi-jurisdiction. Opinion-grade. Agent-native.
**North Star:** `docs/YC-RFS-EVOLUTION.md` — Three-Layer Product Thesis

---

## Current Focus

**Phase 10.5/11: Research complete** — Best practices and modern workflows documented. Ready to build.

Key findings: SARIF severity ≠ CI blocking (separate concerns), upload-sarif@v4 is current, Semgrep action deprecated (CLI-first pattern), official MCP Registry with `server.json` is the distribution path (not just Smithery), AI-drafted rules must never ship as blocking, provenance fields critical for legal defensibility.

All phases 1-10 shipped. 523 tests, tsc clean. 4 jurisdiction packs live.

---

## Three-Layer Architecture

| Layer | Status | What |
|-------|--------|------|
| **1: Agent Infrastructure** | ✅ Shipped | MCP server (8 tools), CLI, structured JSON, remediation, continuous monitoring |
| **2: Compliance Service** | ✅ Shipped | Opinion-grade assessments, agent-native, reform module, SMB tier, MCP hardening, multi-jurisdiction |
| **3: Compliance Brain** | 🔮 Defer | Emerges from monitoring data — don't build separately |

---

## Baseline (main)

- 523 tests passing, `tsc --noEmit` clean
- CLI: scan, audit, report, attest, monitor, compliance-check, reform + agent format + opinion
- MCP server: 8 tools (scan, scan_url, audit, map, opinion, check, compliance_check, reform)
- 4 jurisdiction packs: au-privacy-act, us-ccpa, eu-gdpr, sg-pdpa (stub)
- PrincipleRegistry: jurisdiction-aware principle lookup (replaces switch statements)
- regulationMappings required on findings, regulationPrinciple on questions
- Multi-jurisdiction report generator (AU + US + EU + SG sections)
- Continuous monitoring: webhook receiver, baselines, regression detection, job queue, reporter
- MCP hardening: McpServer, Zod schemas, structuredContent, fail-closed filesystem, DNS pinning, TOCTOU revalidation, opaque resource URIs, error sanitization, AbortSignal cancellation
- Version: v0.4.0 (dynamic read from package.json)

---

## Phase History

| Phase | What | Status | Tests |
|-------|------|--------|-------|
| 1 | Opinion-Grade Assessments | ✅ Merged | 377 |
| 2 | Agent-Native Enhancements | ✅ Merged | 377 |
| 3 | Reform Module | ✅ Merged | 387 |
| 4 | SMB Compliance Tier | ✅ Merged | 394 |
| 5A | MCP Hardening + Security Audit | ✅ Merged | 400 |
| 5 | Sellable Gate (README, v0.3.0) | ✅ Merged | 423 |
| 6 | Jurisdiction Abstraction | ✅ Merged | 423 |
| 7 | US CCPA/CPRA Pack | ✅ Merged | 458 |
| 8 | EU GDPR Subset Pack | ✅ Merged | 502 |
| 9 | YC App Prep (demo, essay, design partner strategy) | ✅ Done | 504 |
| 10-lite | Schema Decoupling + SG PDPA stub | ✅ Done | 523 |

---

## Upcoming

| Phase | What | Timebox | Status |
|-------|------|---------|--------|
| 10-lite | Schema Decoupling | 3-5 days | ✅ Done |
| 10.5 | GitHub Action + MCP Distribution | 1-2 days | 📋 Research done |
| 11 | Rule Authoring Pipeline (demo) | 1-2 weeks | 📋 Research done |
| 12 | Post-MVP (PII tracking, IDE plugins, Docker) | Post-pilot | 🔮 Deferred |

---

## Jurisdiction Packs

| Jurisdiction | Status | Principles | Scanner Rules | Mapping Rules | Questionnaire |
|---|---|---|---|---|---|
| 🇦🇺 au-privacy-act | ✅ Live | 13 APP + NDB | 68 rules | 25 AU rules | 64 questions |
| 🇺🇸 us-ccpa | ✅ Live | 12 CCPA principles | 6 rules | 9 mapping rules | 14 questions |
| 🇪🇺 eu-gdpr | ✅ Live | 14 GDPR principles | 6 rules | 9 mapping rules | 20 questions |
| 🇸🇬 sg-pdpa | 🧪 Stub | 3 PDPA principles | 3 rules | 3 mapping rules | 6 questions |

---

## Competitive Position

- **Direct competitors:** HoundDog.ai ($3.1M seed, PII taint tracking), Privado.ai ($17.5M Series A, governance platform)
- **Clearway's unique wedge:** Only product with AU Privacy Act mapping + deploy gating + fully offline + MCP-native
- **Full analysis:** `docs/COMPETITIVE-LANDSCAPE.md`

---

## Research

- `docs/RESEARCH-PHASE-10.5-11.md` — Merged research (original + Codex cross-examination)
- `docs/RESEARCH-PHASE-10.5-11-SUPPLEMENT.md` — Codex's independent findings (archived)

---

## Risks

- **July 2026 deadline:** Privacy Act reforms create urgency — but the "100K businesses" claim needs verification
- **Validation risk:** No design-partner feedback yet on report shape
- **Competitive risk:** HoundDog and Privado are funded and shipping fast
- **"Multi-jurisdiction" not "global":** Don't claim global coverage until 3+ packs externally validated
- **PII taint tracking gap:** HoundDog's data-flow tracing is technically superior — our pattern-based rules can't track data across function boundaries