# Adapter Strategy Debate — LLM Scanner Integration

**Date:** 2026-05-02  
**Debate ID:** argue_1777680817856_be6f13  
**Agents:** codex-agent (gpt-5.5), gemini-agent (gemini-3.1-pro), copilot-agent (gpt-5.4)  
**Rounds:** 6 | **Turns:** 18 | **Duration:** 11m18s  
**Consensus:** 3/3 — Strict Option C (deterministic-first hybrid)

---

## Context

Three market events in the same week:
1. **Anthropic** launched Claude Security (public beta, Opus 4.7, integrated with CrowdStrike/Palo Alto/SentinelOne/Wiz)
2. **OpenAI** launched GPT-5.5-Cyber for automated cyber defense
3. **Sam Altman** tweeted about protocols equally usable by people and agents

Clearway's `ScannerAdapter` interface already supports plugging in any scanner. The question: should we build LLM-backed adapters now, stay pure deterministic, or something in between?

## Consensus Position

**Strict Option C: Deterministic-first hybrid**

Clearway Core stays offline, deterministic, zero-LLM, default-blocking. That's the trust wedge. AI-backed scanners become opt-in external connectors with provenance-tagged evidence that warns/reviews by default.

**Key framing:** "Offline by default, AI-ingestible by explicit policy."

---

## 15 Accepted Claims (3/3 unanimous on all)

### Strategy Claims

1. **Choose deterministic-first adapters strategy** — Ship adapter contract, conformance suite, provenance model, and policy lanes now. Keep LLM-backed adapters outside Core as opt-in connectors or design-partner pilots, non-blocking by default, not the week-1 headline.

2. **Separate decision authority from evidence ingestion** — Clearway's category is the privacy-compliance deploy decision layer. Scanners supply provenance-tagged evidence in distinct classes (never a blended opaque score). Clearway applies jurisdiction-aware policy to decide block/warn/review.

3. **Zero LLM runtime is a trust asset** — Offline deterministic blocking is a credibility marker because deploy decisions can be reproduced, audited, and reviewed without sending code or evidence to an LLM service. External AI evidence stays outside that core trust boundary.

4. **Prioritizing LLM adapters dilutes the wedge** — Leading with Claude Security or GPT-5.5-Cyber adapters too early repositions Clearway as an AI scanner wrapper instead of a deterministic privacy deploy gate.

5. **AI findings should warn by default** — LLM-backed findings normalize into `AttestLensFinding` but default to warning or human-review lanes. Blocking requires explicit customer policy for validated evidence classes, with corroboration or accountable human approval.

### Architecture Claims

6. **Adapter conformance matters more than vendor adapters** — Publish adapter conformance tests, evidence-class declarations, provenance fields, replay-bundle requirements, and decision-policy semantics before building vendor-specific integrations.

7. **Generic import path reduces vendor lock-in** — After publishing the adapter contract, build a provenance-preserving generic SARIF/JSON import path as the public next step. Private design-partner vendor adapters can validate demand in parallel.

8. **Preserve provenance in reports** — Every ingested finding must carry: source scanner, evidence class, local vs. external execution, scanner & policy versions, confidence/validation status, jurisdiction-mapping basis, resulting policy action, and replay metadata.

9. **Certification levels for adapters** — Classify adapters by certification level (core deterministic, local deterministic third-party, external probabilistic, human-reviewed) so policy defaults and buyer trust are communicated without vendor branding.

10. **No mixed opaque risk score** — Never combine deterministic compliance failures with AI scanner confidence into a single blended score. That erases provenance and makes audits harder.

### Market Claims

11. **Cyber scanner outputs are not compliance determinations** — Claude Security and GPT-5.5-Cyber produce raw security evidence, not privacy-law determinations. Cyber vulnerabilities only affect deploy gates if Clearway's policy explicitly maps them to jurisdictional privacy violations (e.g., GDPR Art. 32).

12. **AI adapters require explicit data-egress controls** — Before shipping any LLM-backed connector, define: data-egress consent, redaction expectations, vendor retention assumptions, and audit logs. These apply only to opt-in external adapters, not Clearway Core.

13. **Vendor adapters should start as enterprise pilots** — First-party Claude Security or GPT-5.5-Cyber adapters should begin as design-partner or enterprise add-ons, not the public launch promise. Validate API stability, precision, provenance, and buyer demand first.

14. **Week-1 launch should stay focused** — Prioritize npm distribution, MCP Registry, GitHub Action, deterministic jurisdiction packs, and paid AU Privacy Deploy Gate Sprints. AI adapter work runs in parallel, not in front.

15. **Publish an open attestation protocol** — Evolve the replay bundle and finding schema into an open, machine-readable attestation protocol that humans, CI systems, MCP clients, and agents can all exchange. This is the long-term moat.

---

## Product Architecture: Two Lanes

| Lane | Source | Default Policy | Trust Level | Blocking? |
|------|--------|---------------|-------------|-----------|
| **Lane 1: Deterministic** | Clearway Core rules | Block | Core certified | Yes |
| **Lane 2: AI-augmented** | External scanners (Claude Security, GPT-5.5-Cyber, SARIF imports) | Warn/Review | External probabilistic | Only via explicit policy promotion |

Both lanes normalize into `AttestLensFinding` with full provenance. Both flow through the same jurisdiction mapping engine. One deploy decision, two evidence sources, transparent audit trail.

## Product Lines

| Product | Description | Status |
|---------|-------------|--------|
| **Clearway Core** | Offline, deterministic, blocking deploy gate | Shipping v0.4.0-beta |
| **Clearway Connectors** | Opt-in external scanner ingestion (SARIF/JSON, Claude Security, GPT-5.5-Cyber) | Design phase |
| **Clearway Policy** | Rules for how evidence classes affect deploy decisions (block/warn/review) | Design phase |

## Adapter Certification Levels

| Level | Type | Default Policy | Examples |
|-------|------|---------------|---------|
| **Core** | Deterministic, shipped with Clearway | Block | APP rules, CCPA rules, GDPR rules, SG PDPA rules |
| **Local 3rd-party** | Deterministic, runs locally (e.g., gitleaks) | Block | Gitleaks secrets detection |
| **External probabilistic** | LLM-backed, requires egress | Warn/Review | Claude Security, GPT-5.5-Cyber |
| **Human-reviewed** | Manual attestation or review | Review | Human compliance sign-off |

## What NOT to Do

- ❌ Don't ship vendor-branded adapters as the public headline
- ❌ Don't let AI findings block deploys by default
- ❌ Don't blend deterministic and AI findings into one opaque score
- ❌ Don't compromise the zero-LLM Core runtime boundary
- ❌ Don't let week-1 scope expand to include adapter integrations

## Scoreboard

| Agent | Score | Correctness | Completeness | Actionability | Consistency |
|-------|-------|-------------|-------------|---------------|-------------|
| copilot-agent | 84.30 | 70.54 | 91.15 | 94.50 | 87.97 |
| codex-agent | 81.53 | 60.71 | 91.67 | 94.50 | 91.58 |
| gemini-agent | 72.73 | 50.67 | 74.33 | 91.50 | 90.28 |

## Related

- First debate (GTM strategy): `docs/GTM-DEBATE-RESULTS.md`
- Market context: Claude Security (May 1, 2026), GPT-5.5-Cyber, Sam Altman agent protocol tweet
- ScannerAdapter interface: `src/scanner/types.ts`
- Phase 11 design: `docs/RULE-AUTHORING-PIPELINE.md`