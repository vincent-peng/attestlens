# AttestLens — Master Development Roadmap

**Last Updated:** 2026-04-27
**Status:** Living document — update as we ship

---

## Current State (v0.2.0)

**What's built:**
- ✅ Core scanner schema + mapping engine
- ✅ GuardVibe adapter (9 static regex + MCP fallback)
- ✅ Supply chain scanner (9 static rules: VS-SC-001→009, plus dynamic OSV findings)
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
- ✅ M3.3 dynamic confidence scoring for APP mappings
- ✅ M3.4 per-adapter timeout and progress plumbing

**What's NOT built yet:**
- ❌ Advisory-monitoring rule update pipeline
- ❌ Executable remote rule migration for all scanner checks
- ✅ OSV.dev vulnerability integration inside supply-chain scanner (M3.1)
- ❌ Behavioral supply-chain analysis (M3.5)
- ❌ Git history secret scanning (M3.6)
- ❌ SAST lite compliance patterns (M3.7)
- ❌ IaC misconfiguration detection (M3.8)
- ❌ Web dashboard (M4 — not until M3 + design-partner validation)

**Current focus:** M3 scanner enhancement (spec at `docs/milestones/M3-SCANNER-ENHANCEMENT.md`). M3.1–M3.4 are implemented; next up is design-partner/report validation before M3.5 behavioral supply-chain analysis. Dashboard is explicitly deferred to M4 — we need validated scanner output and consultant feedback before investing in UI.

---

## Roadmap Overview

```
Phase 1.5 — Scanner Credibility Release    ✅
Phase 2   — Compliance Differentiation      ✅
Phase 2.5 — Rule Update Pipeline (foundation) ✅
Phase 3   — Scanner Enhancement              ← NOW
Phase 3.5 — Rule Update Pipeline (full)
Phase 4   — Platform, Dashboard & AI Integration
Phase 5   — Launch & Growth
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

## Phase 2 — Compliance Differentiation ✅

**Goal:** Build the moat — questionnaire-backed APP/NDB assessment and consultant-grade outputs that generic scanners do not offer.

**Status:** Shipped. Breach-readiness scoring, consultant narratives, attestation validation, and assessment-basis modes all live. Design-partner review in progress.

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

## Phase 2.5 — Rule Update Pipeline ✅ (foundation shipped)

**Goal:** Ensure AttestLens detects new vulnerabilities faster than competitors.

**Shipped:**
- ✅ Rule schema (typed manifest with id, pattern, severity, APP mapping, fixPrompt, CVE, addedIn)
- ✅ Rule loader (embedded pack, cache overlay, corrupt-cache fallback, update command, opt-in auto-update)
- ✅ Rule freshness metadata in scan summaries, MCP output, reports

**Remaining → Phase 3.5:**
- Behavioral heuristics expansion (HEU-001→007)
- Advisory monitoring pipeline
- Rule generator + CI pipeline
- Trust signals (freshness badge, CVE tracking)

See M3 spec (`docs/milestones/M3-SCANNER-ENHANCEMENT.md`) for how behavioral analysis integrates.

---

## Phase 3 — Scanner Enhancement ← NOW

**Goal:** Close competitive gaps and differentiate on compliance-relevant detection.

Full spec: `docs/milestones/M3-SCANNER-ENHANCEMENT.md`

### M3.1 — OSV.dev Vulnerability Integration ✅
- OSV.dev enrichment runs inside the existing `supply-chain` scanner when `--external-enrichment` is enabled, not as a new public scan source
- Batch query by package@version, then fetch unique vulnerability details by OSV ID
- OSV findings emit dynamic `VS-OSV-<OSV_ID>` rule IDs and map to APP_11 plus conditional NDB/APP_8 where vulnerability class supports it
- Graceful fallback when OSV API unavailable via recoverable scanner warnings

### M3.2 — Dependency Provenance Detection ✅
- `VS-SC-009` flags direct production dependencies with no repository and no homepage metadata
- Existing `VS-SC-007` and `VS-SC-008` meanings are preserved
- Local `node_modules/<dep>/package.json` metadata is used by default; npm registry fallback is opt-in via `--external-enrichment` and has recoverable warnings
- Maps to APP_11 and APP_6

### M3.3 — Dynamic Confidence Scoring ✅
- Replace hardcoded confidence with context-aware calculation
- Typosquat distance, auth endpoints, multi-source confirmation, file type
- Makes reports defensible for consultant use

### M3.4 — Per-Adapter Timeout & Progress Reporting ✅
- AbortSignal per adapter, configurable timeouts
- Progress callbacks for CLI feedback
- Partial results on timeout, not hard failure

### M3.5 — Behavioral Supply-Chain Analysis (1 week)
- 6 signals: eval/Function, network access, shell access, env access, obfuscation, high-entropy strings
- No compliance tool does this — highest differentiation opportunity
- Maps to APP_11 + APP_8 + NDB

### M3.6 — Git History Secret Scanning (3 days)
- Gitleaks integration as opt-in adapter (like mcp-scan)
- 150+ secret detectors covering git history
- Maps to APP_11 + NDB — the #1 gap consultants flag

### M3.7 — SAST Lite: Compliance-Critical Patterns (1 week)
- 20 patterns: hardcoded creds, SQL injection, SSRF, CORS wildcard, prototype pollution, path traversal, etc.
- Regex-based, no AST parsing needed
- Direct APP/NDB mappings for each pattern

### M3.8 — IaC Misconfiguration: Dockerfile + Terraform (1 week)
- 15 Dockerfile checks + 10 Terraform checks
- All map to APP_11 + conditional NDB
- Pure TypeScript, no Go runtime needed

### M3.9 — Cross-Scanner Finding Deduplication (1 day)
- Canonical key generation across scanners
- Multi-source findings get confidence boost
- No triple-counting in reports

### M3.10 — Package Maturity Scoring (1 day)
- Weekly downloads, maintainer count, README/tests presence
- Enriches supply-chain findings, strengthens confidence

### Implementation Timeline

```
Week 1-2:  M3.1 ✅ + M3.2 ✅ + M3.3 ✅ + M3.4 ✅  (quick wins + production hardening)
Week 3-4:  M3.5 + M3.6                  (differentiation + consultant value)
Week 5-6:  M3.7 + M3.8                  (extended coverage)
Week 7:    M3.9 + M3.10                 (quality + enrichment)
```

**Exit criteria:**
- All 10 enhancements shipped and tested
- 223+ existing tests still green
- Total detection surface > 250 compliance-relevant rules
- npm audit plus opt-in OSV.dev dual-source CVE coverage
- Behavioral analysis producing findings with APP_11 mappings
- Gitleaks integration working as opt-in adapter
- Reports show deduplicated findings with dynamic confidence scores

**Competitive gap analysis:** See `docs/milestones/M3-SCANNER-ENHANCEMENT.md` for detailed comparison against Semgrep, Socket.dev, Trivy, Snyk, and gitleaks.

---

## Phase 3.5 — Rule Update Pipeline (full)

**Goal:** Complete the rule freshness system started in M2.5.

### Behavioral Heuristics Expansion
- HEU-001 through HEU-007 (pre-staged packages, self-destructing code, obfuscated scripts, rapid bumps, new maintainer, dep count anomaly, DNS/exfil)
- Test against known attacks (Axios Mar 2026, ua-parser-js, event-stream, colors.js)

### Advisory Monitoring + Rule Generator
- `scripts/check-advisories.mjs` — npm, Snyk, CVE NVD
- `scripts/generate-rules.mjs` — template-based rule generation
- GitHub Actions CI: check → generate → test → publish (every 4h)

### Trust Signals
- `CHANGELOG-RULES.md` with dates + sources
- Rules freshness badge in scan output
- Rule count in `--version`
- CVE coverage tracking

**Exit criteria:** 7 new heuristics, advisory monitoring cron, <4h response target.

---

## Phase 4 — Platform, Dashboard & AI Integration (after M3 + design-partner validation)

**Goal:** SaaS-grade product with AI-powered features.

**Prerequisite:** M3 scanner enhancements shipped + 3+ design-partner confirmations that report shape is useful.

**Why dashboard is deferred:** CLI + PDF is sufficient for design-partner validation. Dashboard is a UI wrapper around validated scanner output. Building it before consultants confirm the compliance mapping holds up would be premature. The moat is compliance mapping, not UI.

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

## Phase 5 — Launch & Growth (after M4)

### Beta Launch

| Task | Details |
|------|---------|
| **Landing page** | attestlens.dev — value prop, pricing, demo |
| **Documentation** | Getting started, CLI reference, rule packs, compliance guide |
| **Product Hunt** | Launch day presence |
| **Reddit** | r/micro_saas, r/netsec, r/webdev, r/AustralianPolitics (for APP angle) |
| **X/Twitter** | Thread: "I built a scanner that maps security findings to Australian Privacy Act obligations" |
| **Consultant outreach** | 5-10 AU compliance consultants, free scan + PDF report for feedback |

### Community & Content

| Task | Details |
|------|---------|
| **Community rules** | GitHub Issue + PR templates for rule submissions |
| **Blog series** | Axios post-mortem analysis, Privacy Act Tranche 2 guide, compliance for indie devs |
| **Rule contributions** | Open rule pack submissions, 48h merge target |
| **CVE coverage page** | attestlens.dev/cves — public, searchable |
| **"First to Detect" stories** | Document response times for real vulnerabilities |

### Growth

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

**International pricing note:** When expanding beyond AU (GDPR, SOC 2), pricing should accommodate EUR and USD. Consultant tier may need regional adjustment — EU GDPR consultants operate at different price points than AU APP consultants.

---

## Success Metrics

| Metric | Phase 1.5 | Phase 2 | Phase 3 | Phase 4 |
|--------|-----------|---------|---------|---------|
| Security checks | 68+ | 68+ | 250+ | 300+ |
| Compliance questions | 0 | 50-70 | 50-70 | 70+ |
| Report formats | MD/JSON/HTML | +PDF | +PDF | +PDF |
| URL scanning | ✅ | ✅ | ✅ | ✅ |
| AI fix prompts | ✅ | ✅ | ✅ | ✅ |
| Breach readiness score | ❌ | ✅ | ✅ | ✅ |
| Rule pack system | ❌ | ❌ | ✅ | ✅ |
| Behavioral heuristics | 8 rules | 8 rules | 15+ rules | 15+ |
| CVE sources | npm audit | npm audit | npm audit + opt-in OSV.dev | npm audit + OSV.dev |
| Git history secrets | ❌ | ❌ | ✅ (gitleaks) | ✅ |
| SAST patterns | 8 JS | 8 JS | 28+ (JS + source) | 28+ |
| IaC checks | ❌ | ❌ | 25 (Docker + TF) | 25+ |
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
| Dashboard premature build | Medium | High | Deferred to M4; CLI + PDF is sufficient for validation |
| SAST false positives | High | Medium | Conservative patterns, severity thresholds, fix prompts |
| Gitleaks not installed | High | Low | Opt-in adapter pattern (like mcp-scan); graceful skip |
| OSV.dev API downtime | Medium | Low | Timeout + fallback to npm audit; only used with `--external-enrichment` |

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
| 2026-04-26 | Dashboard deferred to M4 | CLI + PDF sufficient for design-partner validation; moat is compliance mapping, not UI |
| 2026-04-26 | Scanner enhancement before SaaS | Competitive gaps (OSV.dev, behavioral, gitleaks) must close before wrapping in UI |
| 2026-04-26 | M3 milestone formalized | Deep research identified 10 prioritized enhancements; spec at `docs/milestones/M3-SCANNER-ENHANCEMENT.md` |

---

## What We're NOT Building (Yet)

- Mobile app
- Desktop app
- Real-time monitoring (needs infra)
- Multi-region compliance (NZ/GDPR — future packs after M3 validation)
- Team management / org accounts
- Custom rule builder UI
- API marketplace
- Partner integrations (Xero, MYOB)
- **Web dashboard** (deferred to M4 — needs validated scanner output first)

These are all Phase 4+ or never, depending on traction. Dashboard is explicitly blocked on M3 completion + design-partner validation.
