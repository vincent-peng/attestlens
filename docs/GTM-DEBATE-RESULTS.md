# GTM Debate Results — Clearway (2026-05-01)

**Session:** argue_1777592457703_32e177
**Agents:** Codex (gpt-5.5), Copilot (gpt-5.4), Gemini (gemini-3.1-pro-preview)
**Rounds completed:** 3 of 3-5 (terminated early, strong consensus by round 2)
**Claims:** 51 extracted, 25 merged → ~26 surviving

---

## Consensus Decisions

### 1. Pricing: Protected Software Surface, Not Per-Scan or Per-Seat

**UNANIMOUS — all 3 agents converged by round 1**

- **Primary meter: protected repos/pipelines/CI enforcement bundles** with unlimited or fair-use scans
- **Reject per-scan pricing** — it penalizes the exact behavior Clearway wants (frequent agent preflights, every PR check)
- **Reject per-seat as primary axis** — AI coding agents break traditional headcount metrics; seat counts become a secondary admin guardrail, not the billing unit
- **Reject per-jurisdiction-pack as primary** — privacy risk is multi-jurisdiction by default; gating packs undermines the core value. Core packs included in paid plans; private/sector-specific packs = Enterprise expansion
- **Snyk lesson is predictability, not seat pricing** — borrow recurring land-and-expand mechanics, adapt the meter to the agent era
- **Hybrid structure:**
  - **Free**: Local CLI + MCP, 1 private repo, no retained evidence
  - **Pro**: ~$99-199/month per 5 protected repos/pipelines, unlimited scans, core jurisdiction packs, CI gates, MCP, HTML/MD evidence
  - **Enterprise**: ~$15-50K+/year, SSO, self-hosted, custom rules, evidence retention, private packs, named support
- **Do not meter MCP invocations or agent calls** — unlimited inside a subscription so more autonomous scanning = more value, not more billing fear

**Gemini explicitly conceded** its initial per-seat position: *"Per-seat pricing is fundamentally broken in a world where autonomous agents generate the bulk of the code."*

### 2. Design Partners: AU Mid-Market, Warm-Intro, 6-Week CI Pilot

**UNANIMOUS**

- **Target profile:** AU/ANZ mid-market SaaS companies with PII exposure, modern CI (GitHub Actions/GitLab), and active AI/coding-agent adoption
- **Named examples (ranked by warm-intro likelihood, not logo prestige):**
  - Tier 1 (most reachable): Employment Hero, Deputy, SafetyCulture, Eucalyptus, Harrison.ai
  - Tier 2 (good fits, need warmer intro): Culture Amp, Airwallex, Finder, Athena
  - Aspiration (too slow for first pilots): Canva, Atlassian
- **Outreach method:** Founder-led warm intros through AU startup/investor/security networks, NOT broad cold outbound
- **Pilot structure (6-8 weeks, staged):**
  - Week 1: Install + baseline in CI (non-blocking/advisory mode)
  - Weeks 2-4: Shadow mode — triage findings, tune rules, suppress FPs
  - Weeks 5-6: Enable blocking ONLY for high-confidence AU findings
  - Week 7-8: Conversion review — paid contract decision or testimonial
- **Exchange:** Free Pro/Enterprise-lite pilot + founder-led setup + limited custom rules/suppressions → weekly feedback, anonymized metrics, private reference by default, public logo/case study only after clear win
- **Critical addition (Copilot):** Each pilot must include a **pre-agreed paid conversion path** (discounted first annual contract) — validates willingness to pay, not just interest in experimentation
- **Pilot success plan (Codex):** One-page document prevents vague free consulting drift and creates a measurable conversion moment

### 3. Competitive Landscape: Narrow White Space, Honest Framing

**UNANIMOUS — major refinement from initial positions**

- **Do NOT claim "nobody does privacy scanning in CI"** — HoundDog.ai and Privado.ai already occupy this space
- **Direct competitors (privacy-in-code):**
  - **HoundDog.ai**: IDE/CI privacy scanning, PII data-flow detection, RoPA/PIA/DPIA automation, AI/LLM workflow coverage. Claims local/CI execution and agent context.
  - **Privado.ai**: Privacy code scanning, connects privacy governance with code scanning, data mapping
- **Adjacent competitors (AppSec, same CI budget):**
  - Snyk, Semgrep, CodeQL, OWASP ZAP — catch security vulnerabilities (SQLi, XSS, SAST/DAST) but NOT jurisdiction-specific privacy-law mappings with opinion-grade evidence
  - Clearway is **complementary at the product level** but **competes for CI real estate, budget, and champion attention**
- **Adjacent competitors (legal-tech, different workflow):**
  - OneTrust, TrustArc, DataGuidance — own privacy governance, assessments, consent, regulatory research, but sit **upstream/downstream of code shipping**, not inside CI
  - Privado blurs this line by connecting governance with code scanning
- **Clearway's defensible white space:**
  - Deterministic, **jurisdiction-cited** privacy-law deploy gating
  - **Offline execution** — zero cloud dependency, no customer code leaves the environment
  - **Agent-native** local MCP/CLI deployment
  - **High-confidence blocking** with structured, auditable evidence
  - **AU-first legal wedge** (nobody else maps APP/NDB)
- **Required action:** Publish a competitive matrix before YC interviews or public launch

### 4. Launch Strategy: npm Beta After Phase 10-lite

**UNANIMOUS**

- **Timing:** Publish v0.4.0-beta to npm **after Phase 10-lite**, before YC application closes
- **Prerequisite:** Install flow, copy-paste CI templates, and MCP setup recipes must work for external users
- **Sequence:**
  1. Phase 10-lite hardens CLI, docs, GitHub Action, sample reports, pricing page
  2. Publish v0.4.0-beta to npm
  3. Close 1-2 design partner pilots
  4. Show HN or targeted developer/privacy launch (after pilots provide real usage story)
  5. Product Hunt — wait for hosted dashboard or broader SMB workflow
- **Version strategy:** 0.4.x beta → 0.5/0.6 with Phase 11 improvements → 1.0 only after stable rule IDs, schemas, CI gate semantics, and at least 3 design partners or 1 public case study
- **Do not overcommit to open-source** — free local adoption is the strategic requirement, not a formal OSS license. Keep the option open.
- **YC story:** npm package + design partner pipeline + pilot metrics > polished marketing site

### 5. Buyer Persona: Dual-Threaded Motion

**UNANIMOUS**

- **Technical champion (day 1 user):** Engineering lead, platform engineer, AI engineering manager — they own CI and feel the deploy friction
- **Economic buyer (who writes the check):**
  - Pro tier: CTO or VP Engineering (expense-level)
  - Enterprise tier: CISO, head of security, or privacy officer/DPO (budget-level, governance approval)
- **Sales motion:** Two-threaded
  - Thread 1 (engineering): Adopt because it blocks risky deploys and automates privacy review
  - Thread 2 (compliance/legal): Endorse because it generates auditable, jurisdiction-cited evidence
  - CTO/CISO pays because AI coding creates board-level governance exposure
- **Privacy/compliance is an approver, not the discoverer** — they don't find the tool first, but their endorsement unblocks enterprise spend

### 6. MCP/Agent Distribution: Free Wedge, Monetized Team Layer

**UNANIMOUS**

- **MCP is the free adoption wedge** (YC RFS #12 "Software for Agents")
  - Coding agents call scan, map, check, opinion tools before proposing or merging code
  - This is the **compliance permission layer** that makes autonomous coding safe to merge
- **CI enforcement is the monetized team layer**
  - Retained evidence, policy management, dashboards, private rules, SSO, self-hosting
  - Revenue expands with more governed surfaces, not per-agent-call
- **Concrete artifacts needed day 1:**
  - Copy-paste GitHub Action / CI template
  - MCP install docs for Cursor, Claude Code, Codex workflows
  - Agent policy examples (e.g., "run attestlens check before merge")
  - Local preflight command for agent workflows
- **Don't over-abstract into "agent infrastructure"** — ground it in specific deploy-gate pain: "agents check privacy-law risk before code is merged"

---

## Action Items (Priority Order)

1. **Build GitHub Action** — Copy-paste CI template for design partners and YC demo
2. **Create MCP agent setup recipes** — Cursor/Claude Code/Codex integration docs
3. **Build competitive matrix** — HoundDog, Privado, Snyk, Semgrep, OneTrust comparison table
4. **Write one-page pilot success plan template** — Prevents free consulting drift
5. **Build ranked AU design partner list** — 20-30 targets ranked by warm-intro path + PII exposure
6. **Update PRICING.md** — Protected surface model, reject per-scan/per-seat
7. **Publish v0.4.0-beta** — After Phase 10-lite, before YC application
8. **Start design partner outreach** — Warm intros through AU networks, parallel with Phase 10-lite

---

## Key Quotes

> "Per-seat pricing is fundamentally broken in a world where autonomous agents generate the bulk of the code." — Gemini (conceding)

> "The product should encourage frequent deploy-gate and agent preflight usage." — Codex

> "For the first design partner, trust and speed outweigh brute-force outbound volume." — Copilot

> "Clearway should not claim that nobody does privacy scanning in CI; it should instead claim a specific agent-native, deterministic, jurisdiction-cited deploy-gate position." — Codex

> "MCP is the free adoption wedge for agent workflows, while CI enforcement, evidence retention, policy management, and enterprise controls form the monetized team layer." — Consensus