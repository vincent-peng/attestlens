# Documentation Consolidation Plan

**Goal:** Reduce documentation sprawl and make the repo tell one coherent story for YC and design partners.

---

## Current issue

The docs contain several overlapping narratives:

- AU Privacy Act scanner.
- Multi-jurisdiction compliance engine.
- AI-native service company.
- Company brain.
- Software for agents.
- Rule authoring pipeline.
- Deploy gate.
- SMB compliance tool.
- YC RFS mapping.

This makes the product look less focused than the implementation deserves.

The repo should now consolidate around one story:

> Clearway is the deterministic privacy deploy gate for AI-generated software.

---

## Keep as canonical

| File | Action | Reason |
| --- | --- | --- |
| `README.md` | Replace | Main public product story |
| `docs/YC-APPLICATION.md` | Replace | YC-facing narrative |
| `docs/INTERNATIONAL-STRATEGY.md` | Replace | International strategy without overclaiming |
| `docs/ROADMAP.md` | Replace | Validation-first roadmap |
| `docs/PRICING.md` | Replace/update | Align with protected repo/pipeline pricing |
| `docs/COMPETITIVE-LANDSCAPE.md` | Keep/update | Good analysis; add international framing if needed |
| `docs/GAP-ANALYSIS.md` | Keep/update | Useful, but mark which gaps are solved |
| `docs/CI-INTEGRATION.md` | Update | Must include actual workflow examples |
| `docs/RULE-AUTHORING-PIPELINE.md` | Update | It appears partly implemented; reflect reality |
| `docs/INDEX.md` | Replace | Make doc map current |

---

## Add new canonical docs

| File | Purpose |
| --- | --- |
| `docs/IMPLEMENTATION-PHASES-CODEX.md` | Detailed phase plan and prompts for Codex |
| `docs/DESIGN-PARTNER-VALIDATION.md` | 30-day validation sprint |
| `docs/COMPETITIVE-POSITIONING-INTERNATIONAL.md` | Competitor response and YC positioning |
| `docs/DOCS-CONSOLIDATION-PLAN.md` | This cleanup plan |

---

## Archive

Move these to `docs/archive/` rather than deleting immediately:

| File | Reason |
| --- | --- |
| `docs/YC-RFS-EVOLUTION.md` | Superseded by new YC application and roadmap |
| `docs/INTERNATIONAL-DEBATE.md` | Debate transcript; useful archive only |
| `docs/DEBATE-RESULTS.md` | Debate output; useful archive only |
| `docs/GTM-DEBATE-RESULTS.md` | Useful internal archive; not canonical |
| `docs/RESEARCH-PHASE-10.5-11-SUPPLEMENT.md` | Merged into main research doc |
| `docs/PHASE-10-GLOBAL-SCHEMA-DECOUPLING.md` | Appears implemented; keep as historical design doc |
| `docs/COMPETITIVE-GAP-ANALYSIS.md` | Already marked archived/superseded |

---

## Delete only after review

Do not delete immediately. Archive first, then delete after the YC application is submitted and the repo has settled.

Candidates for later deletion:

- stale phase execution plans,
- older debate transcripts,
- duplicated competitive analysis,
- docs with outdated test counts,
- docs that still say AU-only when the product is now multi-jurisdiction.

---

## Update checklist

### Branding

- Use “Clearway by AttestLens” consistently.
- Avoid alternating between AttestLens and Clearway without explaining relationship.
- Suggested convention:
  - Company/project: AttestLens
  - Product/runtime: Clearway

### Product language

Replace:

- “AI compliance scanner”
- “global compliance engine”
- “automated auditor”
- “compliance opinion” as primary phrase

With:

- “privacy deploy gate”
- “agent policy runtime”
- “deterministic deploy decision”
- “coverage-bounded jurisdiction pack”
- “high-confidence blocking, otherwise review”

### Legal language

Every public doc should include:

> Clearway is not legal advice. It is a deterministic technical gate and evidence layer for privacy-risky software changes.

### Command language

Use:

```bash
npx -y --package @attestlens/cli@beta attestlens audit .
```

Avoid ambiguous:

```bash
npx @attestlens/cli@beta audit .
```

### Jurisdiction language

Use:

- “AU pack is deepest.”
- “CCPA/GDPR packs are coverage-bounded.”
- “SG PDPA is beta/stub/portability proof.”
- “Multi-jurisdiction, not global.”

Avoid:

- “fully supports GDPR” unless legally validated.
- “global compliance.”
- “only product” unless verified.

---

## Suggested PR structure

### PR 1 — Docs reset

- README
- YC application
- international strategy
- roadmap
- pricing
- index
- new validation/competitive/Codex docs

### PR 2 — CI gate and demo

- workflows
- example GitHub Action
- demo script
- demo fixture

### PR 3 — Pack trust metadata

- schema changes
- report changes
- tests

### PR 4 — Deploy verdict model

- deployDecision schema
- agent output changes
- SARIF mapping changes

### PR 5 — PR diff mode

- git diff utilities
- CLI/MCP flags
- report sorting

---

## Done state

Docs are consolidated when:

- A new reader can explain the product after reading README only.
- YC application does not rely on old RFS/debate docs.
- There is no contradiction in pricing.
- There is no contradiction in jurisdiction maturity.
- There is no contradiction between “deterministic runtime” and “AI-assisted rule authoring.”
- There is no unverified regulatory deadline claim in public pitch docs.
