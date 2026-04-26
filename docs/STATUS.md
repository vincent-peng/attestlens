# AttestLens — Status

**Last Updated:** 2026-04-26
**Purpose:** Near-term source of truth for product status, current milestone, and next actions.

**Current focus:** M3 scanner enhancement spec complete (`docs/milestones/M3-SCANNER-ENHANCEMENT.md`). Design-partner review continues in parallel. Next implementation: M3.1 (OSV.dev) → M3.2 (no-source-repo) → M3.3 (dynamic confidence) → M3.4 (timeouts).

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
- Interactive questionnaire flow engine with saved sessions, resume support, and frozen per-session question sets
- MCP server with path scan, URL scan, audit, and mapping tools
- HTML, JSON, Markdown, and PDF reporting
- Strict mode (`UNKNOWN -> FAIL`)
- Questionnaire session model, JSON persistence, resume flow, merged report support, and assessment-basis tracking
- Supply-chain scanner with Axios-style attack coverage
- Validation corpus runner with 9 public targets and Markdown summaries
- Attestation validation workflow with scenario manifest, runbook, review template, prep helper, and first validation-cycle log
- Stack-specific repo security checks for Supabase, Firebase, Stripe, Clerk/Auth0, and platform secrets
- URL scanner hardening:
  - shared guarded fetch path
  - SSRF protection across redirects and derived resources
  - deterministic JS byte budgeting
  - corrected source-map probing
  - duplicate Cache-Control to APP_12 path removed
- Assessment-basis correctness follow-up:
  - explicit `artifact_only`, `codebase_only`, and `operator_attested` attestation modes
  - known pre-remediation `1.2` sessions upgrade onto `1.3` using their stored questionnaire bank
  - APP 5 direct-notice branch now has a principle-local gate
  - evidence-limited merged reports now carry `assessment` metadata and cap incomplete outcomes
  - validation helper commands now freeze scenario-recommended assessment modes
- M2 closeout:
  - additive breach-readiness score and confidence model in JSON, HTML, Markdown, PDF, and CLI summaries
  - deterministic consultant-facing narrative sections for executive summary, evidence basis, key risks, principle framing, and remediation focus
  - GuardVibe fallback tests now use deterministic local fixtures
  - `AL-INFRA-006` WordPress admin detection now requires stronger WordPress-login evidence
- M2.5 rule freshness foundation:
  - typed rule-pack manifest and freshness metadata
  - embedded rule pack built from current shipped scanner rules
  - local cache loader with corrupt-cache fallback to embedded rules
  - explicit `attestlens update-rules` cache refresh command that preserves existing caches when no source is configured
  - opt-in `--auto-update` on scan, audit, and attest scan flows that only fetches from configured rule sources
  - bounded local/HTTPS manifest loading with timeout and size caps
  - rule-pack freshness metadata in scan summaries, MCP output, saved snapshots, and reports without local cache paths
  - first executable rule-pack slice for allowlisted GuardVibe fallback static regex rules, limited to metadata overrides and explicit disables

### In Progress

- Design-partner validation and consultant/MSP outreach
- Design-partner feedback tracking in `docs/validation/DESIGN-PARTNER-VALIDATION.md`
- External validation remains required; the 2026-04-25 local gate found no local P0/P1 report-shape issue but does not replace design-partner feedback
- Validation-driven rule cleanup for remaining live-site false positives and CDN/bot-blocked targets

### Not Shipped

- advisory-monitoring rule update pipeline
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
- questionnaire coverage now spans all APP/NDB principles with frozen per-session question sets
- validation-driven remediation patch landed:
  - frozen assessment basis per attestation session
  - APP 3 / APP 5 direct-collection gate for reviewed-surface applicability
  - governance-heavy controls stay `UNKNOWN` in artifact-only and codebase-only runs
  - report sections now distinguish scanner-derived APP 11 evidence from questionnaire assumptions
- correctness follow-up landed:
  - explicit assessment-basis selection is required when resuming pre-`1.3` sessions
  - known `m2-coverage-v1` frozen sessions migrate forward instead of failing closed
  - APP 5 direct notice is reachable in `APP_5`-only runs
  - incomplete merged questionnaire reports no longer emit `A / low-risk`
  - `attest --assessment-mode` and validation-helper recommended modes are wired through
- rule-level fix prompts exist across URL/header/key/JS findings
- mapping engine includes URL-scan categories
- validation corpus and findings log exist
- first attestation validation cycle completed across 3 public scenarios plus 1 sanitized private dry run
- attestation validation runbook, scenarios, local prep helper, and patch queue exist
- stack-specific repo checks exist
- sanitized sample Juice Shop report exists
- breach-readiness scoring and consultant-facing report narratives exist
- `AL-INFRA-006` validation-noise regression coverage exists
- M2 pickup note exists in `docs/milestones/M2-CURRENT-HANDOFF.md`

### Immediate M2 Work

1. Use the refreshed M2 sample reports for design-partner validation.
2. Keep the closeout suite green while collecting report-shape feedback.
3. Keep M2.5 rule freshness compatibility-first while design-partner review runs.

---

## Next Milestones

## M2 — Compliance Moat ✅

**Goal:** Turn the scanner into a real assessment workflow.

- ✅ questionnaire flow engine
- ✅ answer evaluation and confidence scoring
- ✅ merge scan evidence with questionnaire outcomes
- ✅ breach-readiness score
- ✅ consultant-grade report structure

## M2.5 — Rule Freshness (foundation shipped)

**Goal:** Make AttestLens respond to new attack patterns faster than static competitors.

- ✅ rule pack format
- ✅ loader and update command
- ✅ embedded fallback + cache system
- ⏳ new heuristics for modern supply-chain / exfil patterns
- ⏳ advisory monitoring pipeline

## M3 — Scanner Enhancement

**Goal:** Close competitive gaps and differentiate on compliance-relevant detection.

Full spec: `docs/milestones/M3-SCANNER-ENHANCEMENT.md`

- M3.1 — OSV.dev vulnerability integration (2 days)
- M3.2 — No-source-repo dependency detection (2 hrs)
- M3.3 — Dynamic confidence scoring (1 day)
- M3.4 — Per-adapter timeout + progress reporting (2 days)
- M3.5 — Behavioral supply-chain analysis (1 week)
- M3.6 — Git history secret scanning via gitleaks (3 days)
- M3.7 — SAST lite: compliance-critical patterns (1 week)
- M3.8 — IaC misconfiguration: Dockerfile + Terraform (1 week)
- M3.9 — Cross-scanner finding deduplication (1 day)
- M3.10 — Package maturity scoring (1 day)

## M4 — SaaS Wrapper

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

1. Begin M3.1 (OSV.dev integration) and M3.2 (no-source-repo deps) — quick wins.
2. M3.3 (dynamic confidence) and M3.4 (per-adapter timeouts) — production hardening.
3. Continue design-partner outreach with M2 sample reports.
4. Keep `npm test`, `npm run lint`, and `npm run build` green.

### Explicitly Not Now

- SaaS dashboard
- billing
- broad growth automation
- additional compliance frameworks beyond APP/NDB
- SaaS dashboard before M3 scanner enhancements ship
- behavioral analysis before OSV.dev + no-source-repo quick wins

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
