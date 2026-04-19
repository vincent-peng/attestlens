# AttestLens — Status

**Last Updated:** 2026-04-19  
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
- MCP server with path scan, URL scan, audit, and mapping tools
- HTML, JSON, Markdown, and PDF reporting
- Strict mode (`UNKNOWN -> FAIL`)
- Supply-chain scanner with Axios-style attack coverage
- URL scanner hardening:
  - shared guarded fetch path
  - SSRF protection across redirects and derived resources
  - deterministic JS byte budgeting
  - corrected source-map probing
  - duplicate Cache-Control to APP_12 path removed

### In Progress

- Phase 1.5 packaging and release readiness
- Fix-prompt coverage consistency across findings and reports
- Real-world validation prep for consultant and MSP feedback
- Stack-specific detection expansion (Supabase, Firebase, Vercel/Netlify, Stripe, Clerk/Auth0)

### Not Shipped

- Validation corpus and finding-quality log
- stack-specific checks beyond current key/header/JS coverage
- interactive questionnaire flow engine
- breach-readiness scoring
- rule update pipeline
- web dashboard / billing / SaaS operations

---

## Current Milestone

### M1.5 — Scanner Credibility Release

**Goal:** Ship a believable v0.2.0 that can stand beside CheckVibe on scanning credibility while preserving AttestLens's compliance differentiation.

### Exit Criteria

- URL scanning is build-clean, test-covered, and documented
- AI-ready `fixPrompt` support is consistent in schema and rule outputs
- MCP can scan URLs directly
- PDF report generation exists in MVP form
- real-world scans have been run against 5-10 public targets or OSS demo apps
- false positives and misses have been logged and triaged
- docs match the actual repo state

### What Is Already Done Toward M1.5

- URL scanner exists
- URL scanner hardening pass completed
- MCP URL scan tool exists
- PDF report MVP exists
- rule-level fix prompts exist across URL/header/key/JS findings
- mapping engine includes URL-scan categories

### Remaining for M1.5

1. Expand stack-specific checks where the scanner can be meaningfully differentiated.
2. Run real-world scan validation and log findings quality.
3. Keep README / PRD / roadmap aligned as milestone work lands.

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

1. Run validation scans and record false positives, false negatives, and remediation quality.
2. Add the highest-value stack-specific checks.
3. Prepare 3-5 consultant-facing demo artifacts and start outreach.
4. Keep milestone docs aligned as remaining M1.5 work lands.
5. Cut the scanner-credible release once validation is logged.

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
