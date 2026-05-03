# Design Partner Validation — International Agent Privacy Gate

**Goal:** Validate whether teams will run Clearway as a privacy deploy gate for AI-generated code.  
**Timebox:** 30 days.  
**Primary proof for YC:** one real company runs Clearway in CI or shadow mode.

---

## Validation question

The key question is not “is the product technically impressive?”

The key question is:

> Will AI-native SaaS teams let Clearway inspect or gate agent-created code changes before merge?

Everything else is secondary.

---

## Ideal design partner profile

### Must have

- B2B SaaS product.
- Customer or employee PII in the product.
- Active or planned use of AI coding agents.
- GitHub/GitLab CI.
- International customer exposure: US, EU, AU, or multiple.
- Engineering/security leader who can install a CI tool without months of procurement.

### Nice to have

- Privacy review pain.
- Enterprise sales security/privacy questionnaires.
- Recent AI feature launch.
- Compliance pressure from customers or regulators.
- Founder-led urgency.

### Avoid early

- Large banks.
- Government.
- Slow healthcare enterprises.
- Companies without CI.
- Companies that require full legal review before any pilot.

---

## International target tracks

### Track A — US/YC SaaS

Pitch:

> Your coding agents are creating PRs faster than privacy/security can review them. Clearway runs in CI and flags CCPA/GDPR/AU privacy risks before merge.

Best targets:

- AI-native SaaS.
- Devtools companies.
- Customer support automation.
- HR/fintech/health/edtech SaaS.
- Teams using Cursor, Claude Code, Codex, or internal agents.

### Track B — EU-facing SaaS

Pitch:

> Clearway detects GDPR-relevant software changes before release and routes legal/contextual gaps to human review.

Important: do not claim full GDPR compliance. Lead with “coverage-bounded GDPR subset.”

### Track C — AU/ANZ SaaS

Pitch:

> Clearway is Australia-first in depth but international in architecture. It gates agent-generated code against AU Privacy Act and can also run CCPA/GDPR packs.

This remains the best credibility wedge because the AU pack is the deepest.

---

## Pilot structure

### Week 0 — Qualification call

Questions:

1. Are coding agents currently writing PRs or production code?
2. What kinds of customer data does the product process?
3. Which jurisdictions matter commercially?
4. Who reviews privacy risk before merge today?
5. Would a PR-level advisory check be acceptable?
6. What false-positive rate would make this useless?
7. What would need to be true to pay for it?

### Week 1 — Local shadow scan

- Customer runs Clearway locally or in a private CI branch.
- No source code leaves their environment.
- Advisory mode only.
- Produce baseline report.
- Record false positives and useful findings.

### Week 2 — Tuned advisory CI

- Add suppression/tuning where needed.
- Run on PRs or a subset of repos.
- Prioritize newly introduced findings.
- Record time saved and issues caught.

### Week 3 — Limited blocking

- Only high-confidence deterministic rules can block.
- All legal/contextual issues remain `NEEDS_REVIEW`.
- Agree on one or two blocking categories, such as secrets, PII logs, exposed env files, or missing auth on PII routes.

### Week 4 — Conversion decision

- Did it catch something useful?
- Was noise acceptable?
- Would they keep it in CI?
- Would they pay?
- Can they provide a testimonial or anonymized case study?

---

## Pilot success metrics

Minimum evidence for YC:

- One company runs Clearway on a real repo.
- One company says they would keep it in advisory mode.
- False positives are measured.
- At least one actionable finding is found.
- At least one quote or testimonial is captured.

Stronger evidence:

- One paid pilot.
- One company enables high-confidence blocking.
- One company requests custom rules or custom jurisdiction coverage.
- One agent-created PR is blocked and fixed.

---

## Outreach message

Subject options:

- Privacy gate for AI-generated PRs
- Quick question: are coding agents touching customer data?
- Local CI scan for AI privacy risk

Message:

```text
Hi {{name}},

I’m building Clearway, a deterministic privacy deploy gate for AI-generated software.

It runs locally in CI/MCP, scans agent-created code changes, and flags AU/CCPA/GDPR privacy-law risks before merge. No source code leaves your environment.

I’m looking for 3 design partners to run it in shadow mode for two weeks. You get a baseline privacy-risk report, and we tune high-confidence blocking rules together.

This is most useful if your team uses Cursor/Claude Code/Codex or internal coding agents and your product handles customer/employee PII.

Worth a 20-minute call?
```

---

## Call script

Open:

> I’m not trying to sell you a GRC dashboard. I’m trying to understand whether AI-generated PRs need a privacy gate before merge.

Discovery:

- How are coding agents used today?
- What kind of code do agents touch?
- What customer data does your product handle?
- Who owns privacy review?
- How often do privacy/security issues get caught late?
- What scanners are already in CI?
- Would a privacy-specific PR annotation be useful?
- What would make a blocker acceptable or unacceptable?

Demo:

- Show agent-created PR.
- Show Clearway finding.
- Show evidence/citation/confidence.
- Show remediation.
- Show pass after fix.

Close:

> The pilot is local and advisory first. The ask is one repo, two weeks, feedback on false positives, and a conversion conversation if it catches useful issues.

---

## Design partner agreement terms

Lightweight pilot agreement:

- Two-week shadow-mode pilot.
- No source leaves customer environment.
- No legal advice.
- Customer gets baseline report.
- Weekly feedback call.
- Clearway may use anonymized metrics.
- Paid conversion path discussed upfront.

Suggested paid pilot:

- $500–$2,000 for first month, founder-led support.
- Or free pilot with pre-agreed $199/month or $2k/year conversion if useful.

Do not run unlimited free pilots with no conversion path.

---

## What to log

Create a simple CRM sheet:

- company,
- segment,
- jurisdictions,
- coding agent usage,
- PII exposure,
- current scanners,
- buyer persona,
- objections,
- willingness to install,
- willingness to pay,
- pilot status,
- findings count,
- false positives,
- quote.

---

## Common objections and responses

### “We already have Snyk/Semgrep/CodeQL.”

Response:

> Great. Clearway is not replacing SAST. It maps privacy-relevant software changes to jurisdiction-specific deploy decisions and routes ambiguous legal/contextual issues to review.

### “Compliance belongs to legal, not CI.”

Response:

> Legal should define policy, but agent-created code needs a pre-merge guardrail. Clearway is the technical enforcement layer, not the legal authority.

### “False positives will block us.”

Response:

> The pilot starts advisory-only. Blocking is limited to high-confidence deterministic rules after tuning.

### “We cannot send code to a vendor.”

Response:

> The runtime is local/offline. No source code leaves your environment in the pilot.

### “GDPR is too contextual.”

Response:

> Correct. Clearway does not pretend to automate all GDPR conclusions. Contextual obligations become NEEDS_REVIEW with evidence, not false pass/fail claims.

---

## Decision after 30 days

Continue if:

- 3+ teams run scans or pilots.
- At least 1 team wants to keep it in CI.
- False positives are manageable.
- Buyers understand the agent privacy gate story.

Pivot if:

- Teams only want reports, not gates.
- CI installation is a blocker.
- Findings are too generic.
- Privacy/security buyers do not connect agent PRs to privacy risk.

Pivot path:

> AI-native privacy review service for agent-generated software changes.
