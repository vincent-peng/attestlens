# AttestLens — Master Development Roadmap

**Last Updated:** 2026-04-19
**Status:** Living document — update as we ship

---

## Current State (v0.1.0)

**What's built:**
- ✅ Core scanner schema + mapping engine (19 APP/NDB rules)
- ✅ GuardVibe adapter (9 static regex + MCP fallback)
- ✅ Supply chain scanner (8 rules: VS-SC-001→008)
- ✅ Scanner orchestrator (parallel, dedup, disable flags)
- ✅ CLI: `scan`, `audit`, `report` commands
- ✅ MCP server: 3 tools for AI editor integration
- ✅ Report generator: HTML, JSON, Markdown
- ✅ 55 tests passing, 0 npm vulnerabilities
- ✅ Security audit: 2 CRITICAL issues fixed

**What's NOT built yet:**
- ❌ URL scanner (HTTP-based remote scanning)
- ❌ AI fix prompts per finding
- ❌ PDF report generation
- ❌ Interactive compliance questionnaire
- ❌ Rule update pipeline
- ❌ Stack-specific checks (Firebase, Vercel, etc.)
- ❌ Web dashboard

**Codebase:** ~4,500 lines TypeScript, 6 modules, 6 test files

---

## Roadmap Overview

```
Phase 1.5 — Close the Scanner Gap        ← NOW (Weeks 1-2)
Phase 2   — Compliance Differentiation     ← Weeks 3-6
Phase 2.5 — Rule Update Pipeline          ← Weeks 5-7
Phase 3   — Platform & AI Integration     ← Weeks 8-14
Phase 4   — Launch & Growth               ← Weeks 12-16
```

---

## Phase 1.5 — Close the Scanner Gap (Weeks 1-2)

**Goal:** Match CheckVibe's core scanning capability so we're not inferior on security checks.

### Week 1: URL Scanner + AI Fix Prompts

| Day | Task | Details |
|-----|------|---------|
| D1-2 | **URL Scanner** | `src/scanner/url-scan.ts` — HTTP-based remote scanning |
| | | - `fetch(url)` → response headers + HTML |
| | | - Parse `<script src>` → fetch JS bundles |
| | | - Pattern-match exposed keys (15+ patterns) |
| | | - Check security headers (12 checks: CSP, HSTS, X-Frame, etc.) |
| | | - Check infrastructure (.git, .env, CORS, SSL/TLS) |
| | | - Zero new dependencies (Node.js built-in `fetch`) |
| D3 | **AI Fix Prompts** | Schema change + template engine |
| | | - Add `fixPrompt` field to `AttestLensFinding` |
| | | - Template per rule category (code-level vs config-level) |
| | | - Cursor/Copilot-ready prompt generation |
| | | - Example: "Fix the critical security issue: Exposed Supabase service_role key..." |

### Week 2: PDF Reports + Stack-Specific Checks + MCP URL Tool

| Day | Task | Details |
|-----|------|---------|
| D4-5 | **PDF Report Generation** | Puppeteer pipeline from existing HTML |
| | | - `src/report/pdf-generator.ts` |
| | | - `--format pdf` CLI flag |
| | | - Consultant-grade: A4, branded header, APP references, findings table |
| | | - Executive summary (1-page for boards) |
| D6-8 | **Stack-Specific Checks** | Expand static regex patterns |
| | | - Firebase: missing Firestore rules, exposed Admin SDK |
| | | - Vercel/Netlify: `_headers`/`netlify.toml` analysis |
| | | - Stripe: live mode keys, webhook secrets |
| | | - Supabase: RLS policy checks, anon key exposure |
| | | - Convex: `convex/` directory misconfig |
| | | - Clerk/Auth0: exposed secrets, JWT misconfig |
| | | - OpenAI/Anthropic: API key patterns |
| D9 | **MCP: Add URL scan tool** | New `scan_url` tool in MCP server |
| | | - Accept URL input, call URL scanner, return findings |
| D10 | **Integration tests + docs** | Update README, test all new features, tag v0.2.0 |

**Exit criteria:** 68+ checks, zero external deps, URL scanning, AI fix prompts, PDF reports.

---

## Phase 2 — Compliance Differentiation (Weeks 3-6)

**Goal:** Build the moat — features no competitor has.

### Week 3-4: Interactive Compliance Questionnaire

| Day | Task | Details |
|-----|------|---------|
| D1-2 | **Question bank** | 50-70 questions mapped to APP sub-obligations |
| | | - APP 1-13: 3-5 questions each |
| | | - NDB s26WE: 5 questions |
| | | - Add APP 2, 4, 7, 9, 12 (currently zero questions) |
| | | - Question types: yes/no, yes/no/evidence, multi-choice, checklist, scale |
| D3-4 | **Flow engine** | `src/questionnaire/flow.ts` |
| | | - Branching logic (skip APP 8 follow-ups if no overseas disclosure) |
| | | - Confidence scoring per answer |
| | | - Pre-populate from scan findings where possible |
| D5 | **Session management** | `src/questionnaire/session.ts` |
| | | - Save/resume (JSON file) |
| | | - Progress tracking |
| D6-7 | **Evaluator** | `src/questionnaire/evaluator.ts` |
| | | - Answer → PASS/FAIL/UNKNOWN with confidence |
| | | - Merge questionnaire results with scan findings |
| | | - UNKNOWN controls → PASS/FAIL after questionnaire |
| D8 | **CLI command** | `attestlens attest ./my-project` |
| | | - Interactive prompts with `inquirer` |
| | | - Auto-launch after scan (`--attest` flag) |
| D9-10 | **Tests** | Full test suite for questionnaire module |

### Week 5-6: Breach Readiness Score + Enhanced Reports

| Day | Task | Details |
|-----|------|---------|
| D1-3 | **NDB Breach Readiness Score** | Aggregate findings + questionnaire → single score |
| | | - Weighted by APP/NDB relevance |
| | | - Grade: A-F with breakdown by APP principle |
| | | - "If you had a data breach tomorrow, how ready are you?" |
| D4-5 | **Enhanced PDF Reports** | Consultant-grade deliverables |
| | | - White-label support (consultant branding) |
| | | - Cover page with org name + date |
| | | - Executive summary (1-page) |
| | | - Detailed findings with APP references |
| | | - Compliance scorecard by APP principle |
| | | - Remediation roadmap (prioritized) |
| D6-7 | **Breach readiness visualization** | Dashboard-style scorecard in HTML/PDF |
| D8 | **AI report narrative** | LLM-written executive summaries |
| | | - Provider/model config (OpenAI, Anthropic, local) |
| | | - Fallback to template if no API key |
| D9-10 | **Integration testing** | End-to-end: scan → attest → report → PDF |

**Exit criteria:** Full compliance assessment workflow, 50-70 questions, breach readiness score, white-label PDF.

---

## Phase 2.5 — Rule Update Pipeline (Weeks 5-7, overlaps with Phase 2)

**Goal:** Ensure AttestLens detects new vulnerabilities faster than competitors.

### Week 5: Rule Pack System

| Day | Task | Details |
|-----|------|---------|
| D1-2 | **Rule schema** | JSON format with id, pattern, severity, APP mapping, fixPrompt, CVE, addedIn |
| | | - `src/scanner/rules/core.ts` (embedded) |
| | | - `src/scanner/rules/loader.ts` (embedded + remote) |
| D3 | **Rule loader** | Load from embedded pack, then overlay remote updates |
| | | - `attestlens update-rules` CLI command |
| | | - `--auto-update` flag on scan |
| | | - Rule freshness timestamp in scan output |
| D4 | **Migrate existing rules** | Convert 9 static regex + 8 supply chain → rule pack format |
| D5 | **Test** | Verify embedded + remote loading, offline fallback |

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
| Puppeteer dependency size | Low | Low | Optional dep, CLI works without PDF, `--format html` alternative |
| Solo dev bandwidth | High | High | Prioritize ruthlessly; Phase 1.5 first, validate before Phase 2 |

---

## Decision Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-04-18 | URL scanner before questionnaire | Can't sell compliance tool that looks inferior on security |
| 2026-04-18 | PDF via Puppeteer, not PDFKit | Fidelity from HTML rendering; dep only needed for PDF |
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