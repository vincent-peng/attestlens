# Clearway Documentation Index

**Product:** Clearway by AttestLens  
**Current positioning:** Deterministic privacy deploy gate for AI-generated software  
**Status:** International YC reset, follow-up cleanup

---

## Start here

| Doc | Purpose |
| --- | --- |
| [README.md](../README.md) | Public product story and quickstart |
| [YC-APPLICATION.md](YC-APPLICATION.md) | YC-facing narrative and application draft |
| [INTERNATIONAL-STRATEGY.md](INTERNATIONAL-STRATEGY.md) | Multi-jurisdiction strategy without overclaiming |
| [ROADMAP.md](ROADMAP.md) | Validation-first roadmap |
| [IMPLEMENTATION-PHASES-CODEX.md](IMPLEMENTATION-PHASES-CODEX.md) | Phase-by-phase implementation prompts for Codex |

---

## Go-to-market and validation

| Doc | Purpose |
| --- | --- |
| [DESIGN-PARTNER-VALIDATION.md](DESIGN-PARTNER-VALIDATION.md) | 30-day design partner sprint |
| [PRICING.md](PRICING.md) | Protected repo/pipeline pricing model |
| [COMPETITIVE-POSITIONING-INTERNATIONAL.md](COMPETITIVE-POSITIONING-INTERNATIONAL.md) | How to position against scanners, GRC, and frontier models |
| [COMPETITIVE-LANDSCAPE.md](COMPETITIVE-LANDSCAPE.md) | Deeper HoundDog/Privado notes; should be treated as reference and periodically re-verified |

---

## Technical docs

| Doc | Purpose | Status |
| --- | --- | --- |
| [CI-INTEGRATION.md](CI-INTEGRATION.md) | CI/CD setup and SARIF workflows | Real workflow artifact added; tune thresholds after pilot feedback |
| [RESEARCH-PHASE-10.5-11.md](RESEARCH-PHASE-10.5-11.md) | SARIF/MCP/rule-authoring research | Keep as reference |
| [SUPPLY-CHAIN-DETECTION.md](SUPPLY-CHAIN-DETECTION.md) | Supply-chain detection architecture | Keep as reference; external incident claims should be re-verified before public use |
| [ADAPTER-STRATEGY-DEBATE.md](ADAPTER-STRATEGY-DEBATE.md) | LLM scanner adapter strategy | Reference only; market claims need re-verification |
| [archive/RULE-AUTHORING-PIPELINE.md](archive/RULE-AUTHORING-PIPELINE.md) | Historical rule-authoring design | Archived; current execution plan is in IMPLEMENTATION-PHASES-CODEX.md |
| [archive/RULE-UPDATE-PIPELINE.md](archive/RULE-UPDATE-PIPELINE.md) | Historical rule update architecture | Archived reference |

---

## Operational docs

| Doc | Purpose |
| --- | --- |
| [STATUS.md](STATUS.md) | Current implementation status |
| [GAP-ANALYSIS.md](GAP-ANALYSIS.md) | Older gap analysis; useful but should be reconciled with the reset roadmap |
| [DOCS-CONSOLIDATION-PLAN.md](DOCS-CONSOLIDATION-PLAN.md) | What was kept, replaced, and archived |
| [WEB-PRESENCE.md](WEB-PRESENCE.md) | Landing-page/web-portal decision |

---

## Already archived

The reset moved older planning docs into `docs/archive/`:

| Archived doc | Reason |
| --- | --- |
| `archive/YC-RFS-EVOLUTION.md` | Superseded by YC application + roadmap |
| `archive/INTERNATIONAL-DEBATE.md` | Debate transcript, not canonical |
| `archive/DEBATE-RESULTS.md` | Debate output, not canonical |
| `archive/GTM-DEBATE-RESULTS.md` | Internal planning archive |
| `archive/RESEARCH-PHASE-10.5-11-SUPPLEMENT.md` | Merged/supplemental archive |
| `archive/PHASE-10-GLOBAL-SCHEMA-DECOUPLING.md` | Historical phase doc; appears implemented |
| `archive/COMPETITIVE-GAP-ANALYSIS.md` | Superseded by competitive landscape |
| `archive/RULE-AUTHORING-PIPELINE.md` | Historical design; current plan lives in IMPLEMENTATION-PHASES-CODEX.md |
| `archive/RULE-UPDATE-PIPELINE.md` | Historical design; current plan lives in IMPLEMENTATION-PHASES-CODEX.md |

---

## Canonical product language

Use this:

> Clearway is the deterministic privacy deploy gate for AI-generated software.

Avoid this:

- global compliance engine,
- AI auditor,
- generic privacy scanner,
- legal advice,
- company brain as primary product,
- AU-only compliance tool.

---

## Canonical command pattern

Use:

```bash
npx -y --package @attestlens/cli@beta attestlens audit . --jurisdiction eu-gdpr --opinion --format agent
```

For MCP:

```bash
npx -y --package @attestlens/cli@beta attestlens-mcp
```

---

## Canonical YC demo

> Agent creates privacy-risky PR → Clearway runs in CI/MCP → gate returns BLOCK/WARN/NEEDS_REVIEW with evidence → agent fixes → gate passes.
