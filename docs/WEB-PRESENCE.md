# Clearway — Web Presence Decision

**Last Updated:** 2026-05-01
**Question:** Do we need a website? A web portal?

---

## Website: YES (Landing Page, Pre-Launch)

A **landing page** at clearway.ai is needed before npm publish and YC application. Not a full site — a single page that:

1. **States the positioning** — "The deploy gate for AI privacy risk"
2. **Shows the demo** — embedded terminal GIF/video of multi-jurisdiction scan
3. **Has a CTA** — "npm install -g @attestlens/cli" or "Get started" → docs
4. **Lists features** — 3 jurisdictions, 8 MCP tools, CI gating, offline
5. **Links to docs/GitHub** — when we publish the repo

**What it is NOT:**
- Not a SaaS dashboard
- Not a docs site (use docs.hounddog.ai model — separate subdomain later)
- Not a marketing-heavy product page (too early for that)

**When:** Before npm 0.4.0-beta publish. Can be a simple static site (Next.js static export, Astro, or even a single HTML file). Deploy to Vercel/Cloudflare Pages.

**Priority:** Medium — nice to have for YC, not blocking Phase 10-lite.

---

## Web Portal: NO (Not Now)

A **web portal** (dashboard, SaaS platform, user accounts) is **not needed** for any of our current goals:

| Goal | Needs Portal? | What Instead |
|---|---|---|
| YC application | ❌ | CLI demo + landing page |
| npm publish | ❌ | CLI + docs |
| Design partner pilot | ❌ | CLI + CI Action + local reports |
| Pro tier monetization | ❌ | License key in CLI binary |
| Enterprise sales | Eventually | But not until you have 3+ paying enterprises asking for it |

**Why NOT now:**
- We're selling **CLI + MCP + CI gating** — all local. A portal adds zero value to the core workflow.
- Portal = auth, hosting, database, billing, frontend — massive scope creep.
- Privado's portal is their *entire product*. HoundDog has a cloud platform for reporting. We're different on purpose — local-first, offline-capable.
- Every hour spent on a portal is an hour not spent on Phase 10-lite, GitHub Action, or design partner outreach.

**When to reconsider:**
- When 3+ enterprise customers ask for team dashboards / evidence retention across orgs
- When compliance teams (not just engineers) want a UI to review findings
- When you need a billing portal for self-serve Pro signups
- **Earliest:** post-1.0, after design partner feedback

**Minimum viable portal (if forced):**
- Evidence retention API (store scan results in cloud)
- Team dashboard (see all repos, findings, blocking status)
- Billing/subscription management
- Estimated scope: 4-6 weeks for a single developer

---

## Decision

| Item | Decision | Priority | When |
|---|---|---|---|
| Landing page | ✅ Build | Medium | Before npm beta (after Phase 10-lite) |
| Docs site | ⏳ Later | Low | After npm beta, when external users exist |
| Web portal / dashboard | ❌ Defer | — | Post-1.0, post-design-partner-feedback |

Build the landing page in an afternoon. Ship Phase 10-lite first.