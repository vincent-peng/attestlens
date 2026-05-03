# Clearway Status — International YC Reset

**Product:** Clearway by AttestLens  
**Current positioning:** Deterministic privacy deploy gate for AI-generated software  
**Status date:** 2026-05-02

---

## Executive status

Clearway has enough implementation to test the market. The next bottleneck is not more features; it is validation.

Continue, but narrow:

- Continue as an international agent privacy deploy gate.
- Stop adding broad jurisdictions until pilots validate demand.
- Stop positioning as a generic privacy scanner or compliance platform.
- Focus on CI/MCP deploy-gate proof and design partners.

---

## Shipped strengths

- CLI package and MCP server.
- Deterministic runtime.
- SARIF and exit threshold support.
- Multi-jurisdiction packs.
- AU pack with deepest current coverage.
- Opinion engine.
- Rule-authoring pipeline where AI drafts and humans review.
- Local/offline-first posture.

---

## Strategic risks

| Risk | Severity | Mitigation |
| --- | --- | --- |
| No external validation | Critical | 30-day design partner sprint |
| Looks like HoundDog/Privado clone | High | Lead with deploy gate + agent PR workflow |
| Overclaims global compliance | High | Coverage-bounded packs and validation status |
| False positives block adoption | High | Advisory first, block only high-confidence deterministic rules |
| Weak data-flow depth | Medium | Add taint-lite after pilots |
| Brand confusion | Medium | Standardize: Clearway by AttestLens |

---

## What is ready for YC

Ready:

- Demoable CLI/MCP concept.
- Strong deterministic-runtime story.
- Agent-native integration story.
- International pack architecture.
- Rule-authoring pipeline story.

Not ready:

- Customer proof.
- Validated non-AU pack claims.
- Real CI gate demo in repo.
- PR-diff mode.
- Low-false-positive customer data.

---

## Immediate next milestones

1. Docs reset.
2. CI gate workflow and demo PR.
3. Pack coverage/validation metadata.
4. Design partner sprint.
5. PR-diff mode.
6. Evidence graph lite.

---

## Stop/pivot criteria

Stop or pivot if 50 targeted outreaches produce no credible design partner interest.

Pivot path:

> AI-native privacy/security review service for agent-generated software changes.

Use the same engine, but sell a service outcome first.
