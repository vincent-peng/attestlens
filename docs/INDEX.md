# Clearway Documentation Index

**Product:** Clearway by AttestLens  
**Current positioning:** Deterministic privacy deploy gate for AI-generated software  
**Status:** International YC reset

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
| [COMPETITIVE-LANDSCAPE.md](COMPETITIVE-LANDSCAPE.md) | Existing deep dive on HoundDog and Privado |

---

## Technical docs

| Doc | Purpose | Status |
| --- | --- | --- |
| [CI-INTEGRATION.md](CI-INTEGRATION.md) | CI/CD setup and SARIF workflows | Needs update after workflow PR |
| [RULE-AUTHORING-PIPELINE.md](RULE-AUTHORING-PIPELINE.md) | AI-assisted, human-validated rule drafting | Needs update to reflect shipped implementation |
| [RESEARCH-PHASE-10.5-11.md](RESEARCH-PHASE-10.5-11.md) | SARIF/MCP/rule-authoring research | Keep as reference |
| [SUPPLY-CHAIN-DETECTION.md](SUPPLY-CHAIN-DETECTION.md) | Supply-chain detection architecture | Keep as reference |
| [RULE-UPDATE-PIPELINE.md](RULE-UPDATE-PIPELINE.md) | Rule update architecture | Keep as reference |

---

## Operational docs

| Doc | Purpose |
| --- | --- |
| [STATUS.md](STATUS.md) | Current implementation status |
| [GAP-ANALYSIS.md](GAP-ANALYSIS.md) | Known gaps and risks |
| [DOCS-CONSOLIDATION-PLAN.md](DOCS-CONSOLIDATION-PLAN.md) | What to keep, replace, and archive |

---

## Archive candidates

Move to `docs/archive/` after the reset lands:

| Doc | Reason |
| --- | --- |
| `YC-RFS-EVOLUTION.md` | Superseded by YC application + roadmap |
| `INTERNATIONAL-DEBATE.md` | Debate transcript, not canonical |
| `DEBATE-RESULTS.md` | Debate output, not canonical |
| `GTM-DEBATE-RESULTS.md` | Internal planning archive |
| `RESEARCH-PHASE-10.5-11-SUPPLEMENT.md` | Merged/supplemental archive |
| `PHASE-10-GLOBAL-SCHEMA-DECOUPLING.md` | Historical phase doc; appears implemented |
| `COMPETITIVE-GAP-ANALYSIS.md` | Already superseded by competitive landscape |

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
