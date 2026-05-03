# International Strategy — Agent Privacy Gate, Not Global Compliance

**Status:** Replace the older internationalization strategy with this document.  
**Decision:** Continue internationally, but do not claim “global compliance.”  
**Core product:** Deterministic privacy deploy gate for AI-generated software.

---

## Executive decision

Clearway should continue, but the international strategy needs a reset.

The product should not be AU-only. Limiting the YC application to AU makes the company feel too small and too tied to one regulatory event. However, claiming broad global coverage would be a serious credibility mistake.

The right middle path:

> Clearway is an international jurisdiction-pack runtime for agent-created software changes. AU is the deepest seed pack; US/California and EU/GDPR are coverage-bounded expansion packs; new jurisdictions are added only when customer demand or validation justifies them.

---

## New positioning hierarchy

### 1. Category

Agent policy runtime / privacy deploy gate.

### 2. First workflow

AI-generated PRs touching customer data.

### 3. First buyer

AI-native B2B SaaS teams shipping internationally.

### 4. First value

Prevent risky agent-written code from merging without human privacy review.

### 5. First legal scope

Privacy-law technical controls, not full legal compliance.

### 6. Long-term vision

Every AI agent action that touches customer data passes through an evidence-backed policy gate before execution.

---

## What “international” means

International does **not** mean:

- every jurisdiction,
- full GDPR compliance,
- full CCPA compliance,
- legal advice,
- automated auditor replacement,
- “one global compliance score.”

International means:

- same runtime,
- multiple explicit jurisdiction packs,
- pack-level coverage boundaries,
- pack validation status,
- jurisdiction-specific citations,
- different deploy decisions from the same evidence.

Example:

| Same evidence | AU pack | CCPA pack | GDPR pack |
| --- | --- | --- | --- |
| New route logs email + phone | APP 11 fail | Security/privacy review | Art. 32 security review |
| New analytics SDK added | APP 8/6 needs review | sale/share review | Art. 6/13/44 review |
| Missing privacy notice | APP 1 issue | §1798.130 issue | Art. 13/14 issue |

The product’s international power is not broad coverage. It is that the same software evidence can produce different jurisdiction-specific deploy decisions.

---

## Jurisdiction strategy

### Lead jurisdictions for YC

| Jurisdiction | Role | Pitch use | Product maturity target |
| --- | --- | --- | --- |
| AU Privacy Act | Deep proof and founder-market edge | “We proved depth in an underserved regime.” | Strongest pack |
| US CCPA/CPRA | Commercial wedge | “US customers can use this.” | Coverage-bounded pack |
| EU GDPR subset | International credibility | “GDPR-style controls show global relevance.” | Coverage-bounded subset |

### Do not lead with

- Singapore PDPA unless used as a portability demo.
- India DPDP, Brazil LGPD, Japan APPI, UK GDPR, Canada CPPA, etc. until customer demand appears.

### Expansion trigger

Add a new jurisdiction only when one of these is true:

1. A paying customer requires it.
2. A design partner agrees to validate it.
3. A legal/privacy advisor commits to review the pack.
4. The jurisdiction unlocks a concrete buyer segment.

---

## Pack trust hierarchy

Every jurisdiction pack should have a trust state.

| State | Meaning | Runtime behavior |
| --- | --- | --- |
| `draft` | AI/human draft, not validated | Never blocks; never says compliant |
| `internal_validated` | reviewed by founder/team, tests pass | Can warn; limited blocking for deterministic security controls |
| `external_reviewed` | reviewed by privacy/security expert | Can block high-confidence rules |
| `customer_validated` | validated in real customer CI | Can be sold as production gate |
| `legal_partner_validated` | reviewed by counsel/firm | Enterprise-grade pack |

Important rule:

> Unvalidated packs should not emit `COMPLIANT`. They should emit `PASS`, `NEEDS_REVIEW`, or `NO_FINDINGS_IN_SCOPE`, but not legal compliance conclusions.

---

## Runtime decision model

Replace vague compliance language with operational gate language.

Recommended verdicts:

| Verdict | Meaning | CI behavior |
| --- | --- | --- |
| `BLOCK` | high-confidence, validated, deterministic issue | fail build |
| `WARN` | medium-confidence or advisory issue | annotate PR |
| `NEEDS_REVIEW` | legal/contextual evidence missing | route to human |
| `PASS` | no in-scope blocking findings | allow |
| `OUT_OF_SCOPE` | pack cannot assess this obligation | do not infer compliance |

Avoid `COMPLIANT` unless a pack and workflow are externally validated and the scope is tightly stated.

---

## Strategic focus for YC

### Do not pitch

> “We automate global privacy compliance.”

This sounds legally risky and shallow.

### Pitch

> “We are the deploy gate for AI agents touching personal data. We use jurisdiction packs to make pre-merge policy decisions across AU, US, and EU privacy regimes.”

### Best single sentence

> Clearway makes AI coding agents pass privacy-law gates before they merge code.

---

## Product implications

To support the international story, the product must change in these ways:

1. **Coverage boundaries become first-class.** Every report must say what the selected pack can and cannot assess.
2. **Pack validation status becomes first-class.** Every verdict must include pack trust state.
3. **No false “compliant” claims.** Use operational deploy verdicts unless legally validated.
4. **PR-diff mode becomes more important than full-repo scans.** Agents ship changes; Clearway should assess changes.
5. **Agent metadata matters.** Record whether a change was agent-authored, which tool was used, and what evidence was checked.
6. **Design partners matter more than more features.** The next moat is real CI data.

---

## Go-to-market by geography

### US / YC network

Buyer language:

> “Run privacy gates on agent-generated PRs before they merge.”

Target:

- AI-native SaaS
- devtools
- support automation
- HR/fintech/health SaaS
- companies selling internationally

Do not begin with enterprise legal departments. Begin with engineering/security leaders who can install a CI tool.

### EU-facing companies

Buyer language:

> “Detect GDPR-relevant software changes before release; route contextual issues to review.”

Be conservative. Use `NEEDS_REVIEW` for lawful basis, DPIA, transfer, and Art. 22 issues unless evidence is explicit.

### AU/ANZ

Buyer language:

> “Australia-first privacy deploy gate with international packs.”

AU remains your depth wedge and credibility base, but not the ceiling.

---

## 30-day international validation sprint

### Goal

Get proof that companies will install or run Clearway internationally.

### Target metrics

- 50 targeted outreaches.
- 10 calls.
- 3 shadow-mode scans.
- 1 signed design partner or paid pilot.
- False-positive rate measured on at least one real repo.
- At least one customer quote: “I want this in CI.”

### Outreach offer

> I built Clearway, a privacy deploy gate for AI-generated code. It runs locally in CI/MCP and flags AU/CCPA/GDPR privacy risks before agent-written PRs merge. I’m looking for 3 design partners to run it in shadow mode for two weeks. No source leaves your environment. You get a baseline report and we tune high-confidence blocking rules together.

---

## Stop criteria

Stop or pivot if the international gate is not wanted.

Stop/pivot conditions:

- Teams do not see privacy risk as a CI problem.
- They reject installing anything in CI/MCP.
- Findings are too generic compared with existing tools.
- The only interest is post-hoc reports or one-off questionnaires.

Pivot path:

> AI-native privacy/security review service for agent-generated code and vendor security evidence.

The same engine can support that service-first wedge.
