# Clearway — Competitive Landscape

**Last Updated:** 2026-05-01
**Purpose:** Deep-dive on direct and adjacent competitors. Honest assessment of where Clearway overlaps and where it doesn't.

---

## The Honest Answer: Are We Just Another Copy?

**No, but we overlap on "privacy scanning."** Clearway, HoundDog, and Privado all scan code for privacy risks. The surface-level similarity is real. YC will see it. Here's where the product lines actually diverge:

| Dimension | HoundDog.ai | Privado.ai | **Clearway** |
|---|---|---|---|
| **Core thesis** | PII leak prevention via data-flow tracing | Privacy governance platform + AI agent ("Wren") | Jurisdiction-cited deploy gating for AI agents |
| **What they detect** | Sensitive data flows in code (where PII goes) | Data flows + consent + governance + assessments | Regulatory violations mapped to specific law citations |
| **Jurisdiction mapping** | GDPR, CCPA, HIPAA, ISO 29100, NIST (as compliance *frameworks*) | CCPA, GDPR (as compliance checks) | AU Privacy Act, US CCPA, EU GDPR — with per-article **citations** |
| **AU Privacy Act** | ❌ Not supported | ❌ Not supported | ✅ **Uncommon AU APP/NDB focus** |
| **Output** | Data flow maps, PII leak alerts, RoPA/PIA/DPIA reports | Data maps, consent audits, agentic assessments | **Opinion-grade** compliance verdicts (PASS/FAIL/UNKNOWN) with regulatory citations |
| **Blocking** | Advisory (detect, don't block) | Advisory (detect, don't block) | **CI deploy gate** — can block merges on high-confidence findings |
| **Determinism** | Static analysis (taint tracking) | Static + dynamic (web/app simulation) | **Fully deterministic** — zero LLM at runtime, reproducible results |
| **Offline capability** | Partial (CLI binary, but cloud platform for reporting) | No (cloud SaaS platform, web/app auditor) | **Fully offline** — CLI + MCP, zero cloud dependency |
| **Agent integration** | API Context Engine for coding agents | "Wren" AI privacy analyst | **MCP server** — 8 tools callable from any MCP-compatible agent |
| **MCP support** | ❌ No MCP | ❌ No MCP | ✅ Native MCP with structured content |
| **PII taint tracking** | ✅ **Best-in-class** (cross-function, cross-API, cross-transform) | ✅ Good (code scanning + third-party SDK tracking) | ❌ No taint tracking (pattern-based rule engine) |
| **Shadow AI detection** | ✅ Detects AI SDKs in code | ❌ | ❌ Not yet (potential Phase 11+ addition) |
| **IDE plugins** | ✅ VS Code, Cursor, IntelliJ | ❌ (web platform) | ❌ Not yet |
| **Web/app auditing** | ❌ (code-only) | ✅ Web Auditor + App Auditor (live site scanning) | ✅ URL scan (HTTP headers, no runtime simulation) |
| **Governance integration** | OneTrust integration | OneTrust integration, Jira, Slack | ❌ Not yet |
| **Docker image** | ✅ | ✅ (cloud SaaS) | ❌ Not yet |
| **GitHub repo** | github.com/hounddogai/hounddog (111 ⭐) | github.com/Privado-ID (OSS scanner) | Not yet published |
| **Funding** | $3.1M Seed (2023) | $17.5M Series A (2022, Insight + Sequoia India) | Bootstrapped |

---

## HoundDog.ai — Deep Dive

### Company
- **Founded:** 2023, US-based
- **Funding:** $3.1M Seed (Aug 2023)
- **GitHub:** github.com/hounddogai/hounddog (111 stars, 58 forks)
- **Docker:** hub.docker.com/r/hounddogai/hounddog (10K+ pulls)
- **Customers:** Fortune 1000 enterprises (tech + healthcare), Replit integration (45M users)

### Product — Privacy Code Scanner
- **What it does:** Static code analysis that traces sensitive data flows through code transformations, APIs, SDKs, and AI integrations
- **Core strength:** PII taint tracking — follows data across function calls, REST/GraphQL/gRPC APIs, third-party SDKs, and LLM prompts. This is genuinely hard to build and they do it well.
- **Shadow AI detection:** Finds undocumented AI SDKs (LangChain, LlamaIndex, etc.) in code
- **API Context Engine (new):** Feeds API context to coding agents — interesting pivot toward agent infrastructure

### Pricing
| Tier | Price | What |
|---|---|---|
| **Free** | $0/mo | PII leak detection (limited languages/sinks), shadow AI (OpenAI/Anthropic/Gemini only), IDE plugins, CI/CD |
| **Starter** | $100/yr per developer | Full PII leak detection, data flow mapping, shadow AI (all), third-party flows (600+ SDKs), automated RoPA/PIA/DPIA, compliance frameworks (GDPR, CCPA, ISO, NIST, HIPAA), alerts, IDE plugins, CI/CD |
| **Enterprise** | Custom | All Starter + managed scans, SSO, SAST dashboard integration, dedicated support |

**Key observation:** $100/yr per developer is *incredibly* cheap. They're pricing for adoption, not revenue. Seed-funded so they can afford to.

### Where They Beat Clearway
- **PII taint tracking** — they follow data across code boundaries. Clearway does pattern matching against rule definitions. HoundDog's approach is technically superior for finding *where data goes*.
- **IDE integration** — VS Code, Cursor, IntelliJ. Devs see issues as they write code.
- **Shadow AI detection** — no one else does this well.
- **Price** — $100/yr per developer is aggressive.
- **Distribution** — Replit integration, Docker image, GitHub presence.

### Where Clearway Beats Them
- **AU Privacy Act** — they don't support it at all. Zero APP/NDB mapping. This is our unique wedge.
- **Jurisdiction-cited opinions** — HoundDog tells you "PII is leaking to logs." Clearway tells you "this violates APP 11.1 (Security of Personal Information) per Privacy Act 1988 s 21." Different value prop.
- **Deploy gating** — HoundDog detects and advises. Clearway can *block* a CI pipeline.
- **Offline/deterministic** — HoundDog's free tier is a CLI binary, but their reporting platform is cloud. Clearway is fully local, fully deterministic, zero LLM at runtime.
- **MCP native** — HoundDog has no MCP server. Their "API Context Engine" is a separate product for feeding API docs to agents, not for agents to *check compliance*.

### Where They're Headed
The API Context Engine pivot suggests they're moving toward "privacy infrastructure for AI agents" — similar surface to Clearway but different approach (context provision vs. compliance gating). Worth watching.

---

## Privado.ai — Deep Dive

### Company
- **Founded:** ~2021, US/India
- **Funding:** $17.5M Series A (Aug 2022, co-led by Insight Partners + Sequoia Capital India)
- **Open source:** github.com/Privado-ID (free code scanner)
- **AI Agent:** "Wren" — AI privacy analyst

### Product — Privacy Platform
Privado is **not just a code scanner**. It's a full privacy governance platform with four products:

1. **Privacy Code Scanner** — scans source code to map data flows, detect risks, generate data maps
2. **Web Auditor** — scans live websites for consent banner compliance, tracker detection, cookie/data flow mapping ($250/website/month)
3. **App Auditor** — scans mobile apps for SDKs, trackers, consent, data flows ($1,000/app/month)
4. **Agentic Assessments** — AI agent ("Wren") that automates privacy assessments, data maps, risk discovery

### Pricing
| Tier | Price | What |
|---|---|---|
| **Web Auditor** | $250/website/month (annual) | Live site scanning, consent, trackers, data flows |
| **App Auditor** | $1,000/app/month (annual) | Mobile app scanning, SDKs, trackers |
| **Platform** | $4,200/month (annual, up to 200 devs) | Source code scanning, data maps, RoPA/PIA/DPIA, compliance checks |
| **Enterprise** | Custom (200+ devs) | All products combined |

**Key observation:** $4,200/mo for up to 200 devs = ~$21/dev/month. But the real revenue is in the per-website and per-app auditors.

### Where They Beat Clearway
- **Scope** — code + web + mobile. Clearway is code + URL headers only.
- **Governance integration** — OneTrust, Jira, Slack, CDP/tag manager integrations. They sit in the privacy governance workflow.
- **Funding** — $17.5M Series A with tier-1 investors. They have runway and team.
- **AI agent** — "Wren" automates assessments. Clearway's runtime is deterministic (no AI), which is a feature AND a gap.
- **Mobile app scanning** — no one else does this well.
- **Consent monitoring** — live consent banner verification. Clearway doesn't touch consent.

### Where Clearway Beats Them
- **AU Privacy Act** — Privado doesn't support it.
- **Deterministic** — Privado's "Wren" AI agent introduces non-determinism. Clearway's results are 100% reproducible. For CI gating, determinism is a trust requirement.
- **Offline** — Privado is a SaaS platform. Your code goes to their cloud. Clearway runs entirely locally.
- **Deploy gating** — Privado detects and reports. They don't block deploys.
- **MCP native** — Privado has no MCP server. Their "agent" is their own proprietary AI.
- **Price** — $4,200/mo vs. Clearway Pro at ~$199/mo. Different weight class.

### Where They're Headed
"Wren" AI agent + agentic assessments = they're moving toward AI-automated privacy compliance. This is the "AI does everything" path. Clearway's "AI builds rules, runtime is deterministic" is a different bet.

---

## Adjacent Competitors (Same CI Budget, Different Product)

### AppSec Tools (Snyk, Semgrep, CodeQL, OWASP ZAP)
- **What they do:** Security vulnerability scanning (SQLi, XSS, SAST/DAST)
- **Overlap:** Compete for CI real estate, engineering budget, and champion attention
- **Clearway positioning:** Complementary at the product level. "Snyk catches SQL injection. Clearway catches Privacy Act violations. You need both."
- **Risk:** Engineering teams may say "we already have Snyk, we're covered" — need to educate that security ≠ privacy compliance

### Privacy Governance Platforms (OneTrust, TrustArc, DataGuidance)
- **What they do:** Privacy program management, assessments, consent management, regulatory research, DSAR workflows
- **Overlap:** They "own" the privacy compliance budget and workflow
- **Clearway positioning:** Upstream/downstream — they manage the program, Clearway enforces in CI. Privado is trying to bridge this gap.
- **Risk:** They could add code scanning. OneTrust already integrates with HoundDog and Privado.

---

## Clearway's Defensible White Space

1. **AU Privacy Act APP/NDB mapping** — few competitors appear to emphasize this; verify before public claims. If we own AU, we own the wedge.
2. **Jurisdiction-cited deploy gating** — HoundDog and Privado detect issues. Clearway produces an opinion that can *block a CI pipeline*. The difference between "here's a finding" and "this merge is blocked until APP 11.1 is resolved" is the difference between a report and a gate.
3. **Fully offline, fully deterministic** — zero cloud dependency, zero LLM at runtime. For regulated industries and security-conscious orgs, this matters.
4. **MCP-native agent integration** — one of the few products positioned around agent-native privacy-law checks before merging code. HoundDog's API Context Engine feeds context to agents; Clearway's MCP server lets agents *ask about compliance*.
5. **Opinion-grade verdicts** — not "potential issue found" but "FAIL — APP 11.1 Security of Personal Information — confidence: HIGH — remediation: add HSTS header". Actionable, not informational.

---

## What Clearway Must Do to Stay Ahead

1. **Ship AU as the default.** If we don't own AU Privacy Act before HoundDog/Privado add it, we lose the unique wedge.
2. **Ship CI deploy gating.** "Detect" isn't enough. The value is "block." GitHub Action with severity-threshold gates.
3. **Ship MCP recipes.** HoundDog has IDE plugins. Clearway needs equivalent distribution via MCP — Cursor, Claude Code, Codex integration docs.
4. **Add PII taint tracking (Phase 12+).** Currently our biggest technical gap vs. HoundDog. Pattern-matching rules can't trace data across function boundaries.
5. **Never claim "no competitors."** YC will ask. The honest answer: "HoundDog and Privado detect PII leaks. Clearway gates deploys on jurisdiction-cited privacy law violations. Different problem, different output, different buyer motion."

---

## Pricing Comparison

| | Free | Paid | Enterprise |
|---|---|---|---|
| **HoundDog** | $0 (limited) | $100/yr per dev | Custom |
| **Privado** | OSS scanner | $4,200/mo (200 devs) | Custom (200+ devs) |
| **Clearway (proposed)** | $0 (CLI + MCP) | $199/mo per 5 repos | $15-50K+/yr |

HoundDog is pricing for land. Privado is pricing for enterprises. Clearway's proposed pricing sits between — affordable for startups, with the repo-based meter aligning to actual value (protected surfaces).

---

## Bottom Line

Clearway is **not a copy** of HoundDog or Privado. We overlap on "privacy scanning" but diverge on:

- **What we produce:** opinions + citations vs. data flow maps + PII alerts
- **How we enforce:** deploy gates vs. advisory reports
- **Where we run:** fully offline vs. cloud-dependent
- **Who we serve first:** AU Privacy Act (unique) vs. GDPR/CCPA (crowded)
- **How agents use us:** MCP-native compliance checks vs. no agent integration

The risk isn't being a copy — it's being *perceived* as one. That's a positioning and distribution problem, not a product problem. Ship the AU wedge, ship CI gating, ship MCP recipes, and the differentiation becomes obvious in demo.