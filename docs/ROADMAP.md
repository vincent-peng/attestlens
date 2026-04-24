# AttestLens — Master Development Roadmap

**Last Updated:** 2026-04-24
**Status:** Living document — update as we ship

---

## Current State (v0.2.0)

**What's built:**
- ✅ Core scanner schema + mapping engine
- ✅ GuardVibe adapter (9 static regex + MCP fallback)
- ✅ Supply chain scanner (8 rules: VS-SC-001→008)
- ✅ URL scanner with headers, JS, infra, cookies, and source-map checks
- ✅ Scanner orchestrator (parallel, dedup, disable flags)
- ✅ CLI: `scan`, `audit`, `report` commands
- ✅ CLI attestation workflow: `attest <target>`, `attest --from-scan`, `attest --resume`
- ✅ Interactive APP/NDB questionnaire flow with branching, frozen per-session question sets, and resume support
- ✅ Assessment-basis modes: `artifact_only`, `codebase_only`, `operator_attested`
- ✅ Merged report output that combines scanner evidence with questionnaire outcomes
- ✅ Assessment metadata in merged reports, including incomplete-assessment handling for evidence-limited runs
- ✅ MCP server: path scan, URL scan, audit, and mapping tools
- ✅ Report generator: HTML, JSON, Markdown, PDF
- ✅ AI-ready `fixPrompt` support in schema and scanner rules
- ✅ Validation corpus runner + findings log
- ✅ Attestation validation workflow with scenario manifest, prep helper, runbook, and sanitized review log
- ✅ Stack-specific repo checks for Supabase, Firebase, Stripe, Clerk/Auth0, and platform secrets
- ✅ Security hardening including SSRF protection for URL scanning
- ✅ Breach-readiness scoring as an additive report object
- ✅ Consultant-facing deterministic narrative report sections
- ✅ GuardVibe fallback test recovery and `AL-INFRA-006` rule-noise cleanup
- ✅ M2.5 rule-pack foundation with typed manifests, embedded rules, cache fallback, explicit update command, opt-in auto-update, and rule freshness metadata

**What's NOT built yet:**
- ❌ Advisory-monitoring rule update pipeline
- ❌ Executable remote rule migration for all scanner checks
- ❌ Web dashboard

**Current focus:** Run design-partner review from `docs/validation/DESIGN-PARTNER-VALIDATION.md` while keeping the M2.5 rule-pack foundation compatibility-first.

---

## Roadmap Overview

```
Phase 1.5 — Scanner Credibility Release    ← NOW
Phase 2   — Compliance Differentiation
Phase 2.5 — Rule Update Pipeline
Phase 3   — Platform & AI Integration
Phase 4   — Launch & Growth
```

---

## Phase 1.5 — Scanner Credibility Release

**Goal:** Ship a credible v0.2.0 that holds up on scanner quality while preserving AttestLens's compliance-first positioning.

### Done

- URL scanner implementation
- MCP URL scan tool
- PDF report MVP using PDFKit
- rule-level fix prompts in schema and scanner outputs
- SSRF / redirect / derived-resource hardening for URL scanning
- deterministic JS byte budgeting
- duplicate Cache-Control to APP_12 path removed
- expanded regression coverage for URL scanning and mapping behavior

### Outcome

- Stack-specific checks shipped in the repo scanner fallback
- Validation corpus executed against 9 public targets with results logged in `docs/VALIDATION-LOG.md`
- README / PRD / roadmap synced to the current codebase
- v0.2.0 release artifacts prepared, including a sanitized Juice Shop sample report

**Residual risks:** Some live marketing sites intermittently block scans or challenge asset fetches, and a small set of URL heuristics still need precision tuning.

---

## Phase 2 — Compliance Differentiation

**Goal:** Build the moat — questionnaire-backed APP/NDB assessment and consultant-grade outputs that generic scanners do not offer.

### Shipped Foundation

- APP/NDB questionnaire coverage across all principles, including branching/applicability logic
- Attestation session persistence with frozen question sets, resume support, and scan-snapshot integrity checks
- Assessment-basis modes:
  - `artifact_only` for saved/public artifact review
  - `codebase_only` for local repo review without live-process attestations
  - `operator_attested` for real governance/process attestations
- Merged scan + questionnaire reporting in HTML, JSON, Markdown, and PDF
- Attestation validation workflow:
  - scenario manifest
  - prep helper
  - local review template
  - sanitized validation log
- Validation-driven remediation:
  - reviewed-surface collection gates for APP 3 / APP 5
  - governance-heavy principles remain `UNKNOWN` in evidence-limited modes instead of false-failing
  - APP 11 scanner evidence is separated from questionnaire-backed assumptions
  - incomplete evidence-limited merged reports no longer surface as `A / low-risk`
- Breach-readiness scoring rendered in JSON, HTML, Markdown, PDF, and CLI summaries
- Consultant-facing deterministic report narratives before the detailed control checklist
- GuardVibe static-fallback regression fixed with deterministic fixtures
- `AL-INFRA-006` WordPress admin rule tightened to require stronger WordPress-login evidence

### Remaining Phase 2 Work

1. **Final closeout verification**
   - `npm test`, `npm run lint`, and `npm run build` are green as of 2026-04-24
   - use refreshed samples for design-partner review
2. **Routine validation follow-up**
   - continue tuning live-site false positives as new corpus evidence appears

**Exit criteria:** breach-readiness scoring shipped, consultant-facing narrative sections shipped, validation follow-up queue reduced to routine rule tuning, and the attestation/report baseline remains stable under rerun.

---

## Phase 2.5 — Rule Update Pipeline (Weeks 5-7, overlaps with Phase 2)

**Goal:** Ensure AttestLens detects new vulnerabilities faster than competitors.

### Week 5: Rule Pack System

| Day | Task | Details |
|-----|------|---------|
| D1-2 | **Rule schema** | Done: typed manifest with id, pattern, severity, APP mapping, fixPrompt, CVE, addedIn |
| D3 | **Rule loader** | Done: embedded pack, cache overlay, corrupt-cache fallback, `attestlens update-rules`, opt-in `--auto-update` |
| D4 | **Migrate existing rules** | Started: embedded manifest is generated from current GuardVibe, URL, JS, key, infra, and supply-chain rule definitions |
| D5 | **Test** | Started: loader, CLI update, schema, report metadata, and MCP metadata tests exist |

Remaining Week 5 work:

- make selected rule-pack entries executable in scanner paths instead of metadata-only
- define remote publish/source policy before enabling default remote fetches
- decide whether rule freshness should appear in `attestlens --version`

### Week 6: Behavioral Heuristics Expansion

| Day | Task | Details |
|-----|------|---------|
| D1-3 | **7 new heuristic rules** | HEU-001 through HEU-007 |
| | | - Pre-staged packages (new dep <24h before suspicious activity) |
| | | - Self-destructing code (file deletion in postinstall) |
| | | - Obfuscated install scripts (base64/hex in postinstall) |
| | | - Rapid version bumps (>3 versions in 24h) |
| | | - New maintainer + immediate publish (account age <7 days) |
| | | - Dependency count anomaly (sudden many deps) |
| | | - DNS/exfil patterns (hardcoded IPs, fetch to unknown domains) |
| D4 | **Test against known attacks** | Axios (Mar 2026), ua-parser-js, event-stream, colors.js |
| D5 | **Validate** | Run against 3+ real OSS projects, verify no false positives |

### Week 7: Intelligence Pipeline + Trust Signals

| Day | Task | Details |
|-----|------|---------|
| D1-2 | **Advisory monitor** | `scripts/check-advisories.mjs` |
| | | - npm security advisories (GitHub API) |
| | | - Snyk public DB |
| | | - CVE NVD API |
| D3 | **Rule generator** | `scripts/generate-rules.mjs` |
| | | - Template-based rule generation from advisory |
| | | - Auto-map to APP/NDB where applicable |
| D4 | **CI pipeline** | GitHub Actions: check → generate → test → publish |
| | | - Cron: every 4 hours |
| | | - Manual trigger for 0-day response |
| | | - Publish rule pack as GitHub Release |
| D5 | **Trust signals** | - `CHANGELOG-RULES.md` with dates + sources |
| | | - Rules freshness badge in scan output |
| | | - Rule count in `--version` |
| | | - CVE coverage tracking |

**Exit criteria:** Rule pack system live, 7 new heuristics, advisory monitoring cron, <4h response target.

---

## Phase 3 — Platform & AI Integration (Weeks 8-14)

**Goal:** SaaS-grade product with AI-powered features.

### Weeks 8-10: Web Dashboard

| Week | Feature | Details |
|------|---------|---------|
| W8 | **Next.js app scaffold** | React 19 + Vite + Tailwind + shadcn/ui |
| | **Auth** | GitHub OAuth (dev accounts), email/password (consultant tier) |
| | **Project management** | Create project → link repo/URL → scan history |
| W9 | **Scan dashboard** | - URL input → scan → results |
| | | - Findings list with filters (severity, category, APP principle) |
| | | - Compliance scorecard by APP principle |
| | | - Breach readiness gauge |
| W10 | **Report center** | - View HTML/PDF reports |
| | | - Download PDF |
| | | - Share link (expiry, password) |
| | | - White-label settings (consultant tier) |

### Weeks 11-12: AI Integration

| Week | Feature | Details |
|------|---------|---------|
| W11 | **AI-guided attestation** | Dynamic question branching based on scan findings |
| | | AI-suggested answers with confidence scores |
| | | Statutory language translation (plain English ↔ APP/NDB) |
| | | Evidence extraction from code |
| W12 | **AI fix prompts v2** | Contextual code-level remediation |
| | | Mapped to APP obligations |
| | | Copy-paste for Cursor/Copilot/Claude Code |
| | | Multi-fix options (quick fix vs comprehensive) |
| | | Provider/model config (OpenAI, Anthropic, local) |

### Weeks 13-14: SaaS Infrastructure

| Week | Feature | Details |
|------|---------|---------|
| W13 | **Billing** | Stripe integration |
| | | - Free: CLI, local scans, JSON/MD/HTML |
| | | - Pro ($15 AUD/mo): URL scanning, PDF, AI prompts |
| | | - Consultant ($49 AUD/mo): white-label, compliance, unlimited |
| W14 | **CI/CD + Deploy** | Vercel deployment |
| | | CI/CD pipeline (GitHub Actions) |
| | | Staging + production environments |
| | | Monitoring + alerting |

---

## Phase 4 — Launch & Growth (Weeks 12-16)

### Week 12-13: Beta Launch

| Task | Details |
|------|---------|
| **Landing page** | attestlens.dev — value prop, pricing, demo |
| **Documentation** | Getting started, CLI reference, rule packs, compliance guide |
| **Product Hunt** | Launch day presence |
| **Reddit** | r/micro_saas, r/netsec, r/webdev, r/AustralianPolitics (for APP angle) |
| **X/Twitter** | Thread: "I built a scanner that maps security findings to Australian Privacy Act obligations" |
| **Consultant outreach** | 5-10 AU compliance consultants, free scan + PDF report for feedback |

### Week 14-15: Community & Content

| Task | Details |
|------|---------|
| **Community rules** | GitHub Issue + PR templates for rule submissions |
| **Blog series** | Axios post-mortem analysis, Privacy Act Tranche 2 guide, compliance for indie devs |
| **Rule contributions** | Open rule pack submissions, 48h merge target |
| **CVE coverage page** | attestlens.dev/cves — public, searchable |
| **"First to Detect" stories** | Document response times for real vulnerabilities |

### Week 16+: Growth

| Task | Details |
|------|---------|
| **Daily monitoring** | Cron-based re-scans (Pro tier) |
| **GitHub App** | Scan on PR, comment with findings |
| **Slack/Discord bot** | Scan on demand in team channels |
| **API** | REST API for programmatic scanning |
| **Partner integrations** | Xero, MYOB, AU compliance tools |
| **Regional expansion** | NZ Privacy Act, GDPR pack, SOC2 pack |

---

## Pricing Strategy

| Tier | Price | Features | Target |
|------|-------|----------|--------|
| **Free** | $0 | CLI, local scans, JSON/MD/HTML reports, MCP server | Indie devs, OSS |
| **Pro** | $15 AUD/mo | URL scanning, PDF reports, AI fix prompts, 50 scans/mo | Solo devs, small teams |
| **Consultant** | $49 AUD/mo | White-label PDFs, compliance mapping, breach readiness, unlimited scans, priority support | AU compliance consultants, MSPs |
| **Enterprise** | Custom | Self-hosted, SSO, API access, SLA, custom rule packs | Large orgs, government |

Free = current CLI + Phase 1.5. Pro = SaaS wrapper. Consultant = our moat.

---

## Success Metrics

| Metric | Phase 1.5 | Phase 2 | Phase 3 | Phase 4 |
|--------|-----------|---------|---------|---------|
| Security checks | 68+ | 68+ | 68+ | 75+ |
| Compliance questions | 0 | 50-70 | 50-70 | 70+ |
| Report formats | MD/JSON/HTML | +PDF | +PDF | +PDF |
| URL scanning | ✅ | ✅ | ✅ | ✅ |
| AI fix prompts | ✅ | ✅ | ✅ | ✅ |
| Breach readiness score | ❌ | ✅ | ✅ | ✅ |
| Rule pack system | ❌ | ❌ | ✅ | ✅ |
| Behavioral heuristics | 8 rules | 8 rules | 15 rules | 15+ |
| Advisory response time | N/A | N/A | <4h | <2h |
| Paying customers | 0 | 0 | 5 | 20+ |
| MRR | $0 | $0 | $0 | $500+ |

---

## Key Risks & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Market saturation (15+ competitors) | High | Medium | Moat = APP/NDB compliance, not more rules |
| CheckVibe ships compliance first | Low | High | Our compliance engine is already built; they'd start from zero |
| Privacy Act changes delayed | Medium | Medium | Scanner works for any org handling PI; compliance wedge still valid |
| Rule maintenance burden | Medium | Medium | Rule pack system + community contributions + advisory automation |
| PDF generator complexity | Low | Low | Keep PDFKit output deterministic and data-driven; HTML remains fallback |
| Solo dev bandwidth | High | High | Prioritize ruthlessly; Phase 1.5 first, validate before Phase 2 |

---

## Decision Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-04-18 | URL scanner before questionnaire | Can't sell compliance tool that looks inferior on security |
| 2026-04-19 | PDF via PDFKit, not Puppeteer | Lower runtime complexity, deterministic local output, better CLI/MCP fit |
| 2026-04-18 | MCP server first, SaaS later | Zero overhead, global reach via editors |
| 2026-04-18 | Compliance as wedge, not moat | AU checks easy to copy; defensible layer = evidence + attestation + remediation |
| 2026-04-18 | Rule packs independent of npm | Update rules without npm version bump; `attestlens update-rules` |
| 2026-04-18 | Behavioral heuristics over signatures | Socket.dev proved this catches novel attacks; we have the same approach |
| 2026-04-19 | Combined roadmap from all research | Competitive gap + rule pipeline + Phase 2 plan into single document |

---

## What We're NOT Building (Yet)

- Mobile app
- Desktop app
- Real-time monitoring (needs infra)
- Multi-region compliance (NZ/GDPR — future packs)
- Team management / org accounts
- Custom rule builder UI
- API marketplace
- Partner integrations (Xero, MYOB)

These are all Phase 4+ or never, depending on traction.
