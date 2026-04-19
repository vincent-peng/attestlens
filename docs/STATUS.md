# AttestLens — Status

**Last Updated:** 2026-04-20  
**Purpose:** Near-term source of truth for product status, current milestone, and next actions.

---

## Product Position

AttestLens started from the same market pull that made CheckVibe resonate: fast security scanning for AI-built apps, understandable output, and fast fixes for non-security engineers.

The product is **not** trying to beat CheckVibe by becoming a generic scanner clone.

The working thesis is:

- **Scanner parity is table stakes**
- **Australian Privacy Act mapping is the moat**
- **Consultant-grade evidence and reports are the monetizable wedge**

In practice, that means:

- keep enough security coverage to be credible
- translate findings into APP/NDB obligations better than generic tools
- prioritize consultant and privacy-officer workflows over dashboard polish

---

## Snapshot

### Shipped

- Core schema and unified finding contract
- Scanner adapters for GuardVibe fallback, MCP config scanning, supply-chain scanning, and URL scanning
- Scanner orchestrator with parallel execution and deduplication
- APP/NDB mapping engine
- CLI commands: `scan`, `audit`, `report`
- CLI attestation workflow: `attest <target>`, `attest --from-scan`, `attest --resume`
- MCP server with path scan, URL scan, audit, and mapping tools
- HTML, JSON, Markdown, and PDF reporting
- Strict mode (`UNKNOWN -> FAIL`)
- Questionnaire session model, JSON persistence, resume flow, and merged report support
- Supply-chain scanner with Axios-style attack coverage
- Validation corpus runner with 9 public targets and Markdown summaries
- Stack-specific repo security checks for Supabase, Firebase, Stripe, Clerk/Auth0, and platform secrets
- URL scanner hardening:
  - shared guarded fetch path
  - SSRF protection across redirects and derived resources
  - deterministic JS byte budgeting
  - corrected source-map probing
  - duplicate Cache-Control to APP_12 path removed

### In Progress

- Design-partner validation and consultant/MSP outreach
- Phase 2 follow-on work: broader questionnaire coverage, breach-readiness scoring, and report refinement
- Validation-driven rule cleanup for remaining live-site false positives and CDN/bot-blocked targets

### Not Shipped

- interactive questionnaire flow engine
- breach-readiness scoring
- rule update pipeline
- web dashboard / billing / SaaS operations

---

## Current Milestone

### M2 — Compliance Moat

**Goal:** Turn the scanner-credible local product into a real assessment workflow with questionnaire-driven PASS/FAIL outcomes and consultant-grade deliverables.

### Exit Criteria

- questionnaire flow engine exists and can complete a full APP/NDB assessment from the CLI
- scan findings and questionnaire answers merge into a single report
- breach-readiness scoring exists
- sample consultant-grade reports are usable without a web dashboard

### Recently Shipped

- URL scanner exists
- URL scanner hardening pass completed
- MCP URL scan tool exists
- PDF report MVP exists
- `attest` CLI foundation exists with saved scan snapshots, resume support, and questionnaire/report merge
- rule-level fix prompts exist across URL/header/key/JS findings
- mapping engine includes URL-scan categories
- validation corpus and findings log exist
- stack-specific repo checks exist
- sanitized sample Juice Shop report exists

### Immediate M2 Work

1. Expand questionnaire coverage so fewer APP principles remain unresolved after a full attestation.
2. Add breach-readiness scoring and consultant-facing narrative sections on top of the merged report path.
3. Tighten the small set of validation-corpus false positives and intermittent live-site fetch failures.

---

## Next Milestones

## M2 — Compliance Moat

**Goal:** Turn the scanner into a real assessment workflow.

- questionnaire flow engine
- answer evaluation and confidence scoring
- merge scan evidence with questionnaire outcomes
- breach-readiness score
- consultant-grade report structure

## M2.5 — Rule Freshness

**Goal:** Make AttestLens respond to new attack patterns faster than static competitors.

- rule pack format
- loader and update command
- new heuristics for modern supply-chain / exfil patterns
- advisory monitoring pipeline

## M3 — SaaS Wrapper

**Goal:** Add product surfaces only after the local product is validated.

- web dashboard
- AI-guided attestation
- billing and hosted delivery

---

## Execution Rules

These are the default operating rules for the project.

1. Do not start dashboard work before M1.5 is complete and validation feedback exists.
2. Every shipped capability must update either this file or `docs/ROADMAP.md`.
3. Use this file for current status; use `docs/ROADMAP.md` for longer-range sequencing.
4. Prefer scanner correctness and evidence quality over breadth.
5. Treat consultant validation as a gate, not a nice-to-have.

---

## Immediate Priorities

### Next 2 Weeks

1. Start design-partner outreach with the v0.2.0 sample report.
2. Validate the new `attest` flow with real consultant-style runs and tighten the remaining unresolved principles.
3. Add breach-readiness scoring on top of the merged scan + questionnaire baseline.
4. Triage the remaining validation noise (`AL-KEY-011`, `AL-INFRA-006`, duplicate API-key semantics).
5. Keep milestone docs aligned as M2 lands.

### Explicitly Not Now

- SaaS dashboard
- billing
- broad growth automation
- additional compliance frameworks beyond APP/NDB

---

## Risks

- **Validation risk:** the product is still pre-validation; roadmap confidence is higher than customer evidence.
- **Overbuild risk:** dashboard/SaaS work can easily outrun proof of value.
- **Compliance credibility risk:** APP/NDB mapping must remain conservative where automation is weak.

---

## Notes from Origin Context

The original pull from CheckVibe is useful in two ways:

- market proof that fast, AI-app-focused security scanning is a real painkiller
- go-to-market proof that pre-scan outreach and clear findings can convert early customers

AttestLens should borrow the **speed, clarity, and distribution lessons** from that playbook while differentiating on:

- APP/NDB mapping
- evidence-grade reporting
- consultant and white-label workflows
