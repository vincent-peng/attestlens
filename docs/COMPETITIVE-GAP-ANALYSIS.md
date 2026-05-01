# AttestLens Competitive Gap Analysis (Vibe-Scanner Era)

**Date:** 2026-04-18 (updated 2026-05-01)
**Status:** ARCHIVED — preserved for vibe-scanner competitive data

> ⚠️ **This doc is superseded for direct competitor analysis.**
> For current HoundDog.ai + Privado.ai deep-dive with pricing, capabilities, and Clearway differentiation, see **`docs/COMPETITIVE-LANDSCAPE.md`**.
>
> This doc retains useful data on the broader vibe-scanning market (15+ tools) that still informs adjacent competitive positioning.

**Purpose:** Vibe-scanner competitive reference data. For current positioning, see `docs/YC-RFS-EVOLUTION.md`.

---

## 1. Market Landscape (April 2026)

The vibe-coding security scanner market has exploded. There are now **15+ competing tools**, up from 3 a few months ago. Key players:

| Tool | Type | Price | Source Code | Live URL | APP/NDB |
|---|---|---|---|---|---|
| **CheckVibe** | SaaS | £13-55/mo | ❌ | ✅ | ❌ |
| **Vibe App Scanner** | SaaS | $5-29/mo | ✅ | ✅ | ❌ |
| **VibeCheck** (notelon.ai) | Free Web | Free | ✅ | ✅ | ❌ |
| **Aikido Security** | Platform | Free+paid | ✅ | ❌ | ❌ |
| **VibeSecurity** | IDE Plugin | Free+paid | ✅ | ❌ | ❌ |
| **ChakraView** | CLI/OSS | Free | ✅ | ❌ | ❌ |
| **ShipSafe** | SaaS | Free+paid | ✅ | ✅ | ❌ |
| **VibeDoctor** | Web | Free | ✅ | ✅ | ❌ |
| **VibeWrench** | Web | Free | ✅ | ✅ | ❌ |
| **Vibeship Scanner** | Web | Free | ✅ | ✅ | ❌ |
| **amihackable.dev** | Web | Free | ❌ | ✅ | ❌ |
| **WebLegal.ai** | Web | Free | ❌ | ✅ | Partial (AU only) |
| **OneTrust** | Enterprise | $$$$ | ❌ | ❌ | ✅ (full suite) |
| **AttestLens** | CLI/OSS | Free | ✅ | ✅ | ✅ |
| **Shannon** (Keygraph) | CLI+Docker | Lite: AGPL / Pro: Commercial | ✅ | ✅ (live exploit) | ❌ |
| **Pentest-Swarm-AI** (Armur) | CLI+Docker | Apache 2.0 | ✅ | ✅ (live exploit) | ❌ |

**Critical insight:** ZERO tools combine security scanning with Australian Privacy Act (APP/NDB) compliance mapping. That's our moat. But we need to close the security scanning gaps first — nobody will use a compliance tool that can't find vulnerabilities.

**New entrants (April 2026):** Shannon (Keygraph) — autonomous AI pentester. Finds + **proves** exploits (SQLi, XSS, SSRF, auth bypass) with working PoCs. Open-core model (Lite AGPL, Pro commercial). 20+ confirmed vulns in OWASP Juice Shop. **No compliance mapping.** Directly complementary with AttestLens — see §9.

Pentest-Swarm-AI (Armur) — stigmergic swarm pentester. 4 agent types (Recon/Classify/Exploit/Report) coordinate via pheromone-weighted blackboard. Go-based, Apache 2.0, Claude API. MCP server, SARIF output, GitHub Action. Alpha swarm mode. **No compliance mapping.** Complementary — see §10.

---

## 2. CheckVibe Deep Dive

### What CheckVibe Actually Does

CheckVibe is a **URL-based scanner** — you enter a deployed website URL and it scans it in ~30 seconds. It does NOT scan source code locally.

**Their scanning method:**
1. HTTP GET/HEAD to the target URL
2. Fetches all JS bundles, HTML, CSS
3. Pattern-matches for 100+ vulnerability signatures:
   - **Exposed keys:** API keys (OpenAI, Stripe, Firebase, Supabase service_role, Anthropic, etc.) in JS bundles
   - **Security headers:** Missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
   - **CORS:** Wildcard Access-Control-Allow-Origin
   - **BaaS misconfig:** Supabase anon key exposure, Firebase missing rules, Convex config leaks
   - **SSL/TLS:** Certificate issues, weak protocols
   - **XSS vectors:** dangerouslySetInnerHTML, v-html patterns in bundled JS
   - **Info disclosure:** Stack traces, .env exposure, .git exposure, debug endpoints

**Their MCP server** (`@checkvibe/mcp-server` v1.3.2):
- Just a thin MCP wrapper that calls their SaaS API
- Dependencies: `zod`, `@modelcontextprotocol/sdk`
- Runs as `checkvibe-mcp` binary
- Weekly downloads: 10 (tiny — they're selling the web app, not the MCP)

**Their pricing:**
- Starter: £13/mo (1 project, 30 scans/mo)
- Pro: £27/mo (5 projects, 155 scans/mo, daily monitoring, live threat detection)
- Max: £55/mo (25 projects, unlimited, dedicated support)
- Annual = 30% discount

**Revenue signals:**
- Reddit post: "$1k revenue, 50 users" after 1 month (r/micro_saas)
- "Trusted by 500+ developers" on homepage
- £13/mo minimum = they're targeting indie devs with real apps

### What CheckVibe Does NOT Do

- ❌ No local source code scanning (URL only)
- ❌ No dependency/supply chain analysis
- ❌ No compliance mapping (no APP, NDB, GDPR, SOC2 — nothing)
- ❌ No CLI tool (SaaS + MCP only)
- ❌ No privacy impact assessment
- ❌ No data breach readiness scoring
- ❌ No consultant-grade PDF reports with statutory references
- ❌ No questionnaire-based compliance assessment

---

## 3. Gap Analysis: What We Closed in M2

### TIER 1 — Must-Have (we lose to CheckVibe without these)

#### 3.1 Live URL Scanner (HTTP-based)

**What it does:** Point at a deployed URL → get security findings in 30 seconds.

**How to build it:**
- New adapter: `src/scanner/url-scan.ts`
- Uses Node.js `fetch` (built-in since v18) — zero dependencies
- Scan flow:
  1. `fetch(url)` → get response headers + HTML
  2. Parse `<script src="...">` tags → fetch each JS bundle
  3. Pattern-match JS bundles for exposed keys (same regex patterns we already have)
  4. Check security headers (CSP, HSTS, X-Frame-Options, etc.)
  5. Check SSL/TLS via `https` module
  6. Check for common misconfigs (`.git` exposed, `.env` exposed, debug endpoints)

**Effort:** ~2-3 days. Most of the regex patterns already exist in our `staticFallback`.

**Key checks to implement:**
```
HTTP Security Headers (12 checks):
- Content-Security-Policy
- Strict-Transport-Security  
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- X-XSS-Protection (legacy)
- Cross-Origin-Opener-Policy
- Cross-Origin-Resource-Policy
- Cross-Origin-Embedder-Policy
- Cache-Control (sensitive pages)
- Server header info disclosure

Exposed Key Detection (15+ patterns):
- OpenAI API keys (sk-proj-*, sk-*)
- Stripe keys (sk_live_*, pk_live_*)
- Supabase service_role keys
- Firebase Admin SDK keys
- Anthropic API keys
- AWS Access Key IDs
- GitHub Personal Access Tokens
- SendGrid API keys
- Twilio Account SIDs
- Google API keys
- Cloudflare API tokens
- Private keys (-----BEGIN RSA PRIVATE KEY-----)
- Generic api_key/secret_key patterns

JS Bundle Analysis:
- dangerouslySetInnerHTML
- eval() usage
- document.write()
- innerHTML assignment
- window.location injection
- postMessage without origin check

Infrastructure Checks:
- .git/HEAD exposure
- .env file exposure  
- /api/debug endpoints
- /wp-admin exposure
- Server version disclosure
- Cookie Secure/HttpOnly flags
- CORS wildcard
- Open redirect
```

#### 3.2 AI Fix Prompts

**What it does:** Every finding has a copy-paste prompt for Cursor/Copilot/Claude Code.

**How to build it:**
- Add `fixPrompt` field to `AttestLensFinding` schema
- Template system: each rule gets a structured prompt:
  ```
  "Fix the {severity} security issue: {title}.
   In file {file} at line {line}, the code:
   {code}
   
   This is a {category} vulnerability because {description}.
   
   To fix: {fix}
   
   Make the minimal change needed. Do not modify unrelated code."
  ```
- For URL-scan findings (no file/line), generate config-level prompts:
  ```
  "Add the following HTTP security headers to your server configuration:
   - Content-Security-Policy: default-src 'self'; ...
   - Strict-Transport-Security: max-age=31536000; includeSubDomains
   ..."
  ```

**Effort:** ~1 day. Mostly schema change + template strings.

#### 3.3 PDF Report Generation

**What it does:** Consultant-grade PDF with findings, compliance mappings, and remediation roadmap.

**How to build it:**
- **Option A: Puppeteer** — Render our existing HTML report → PDF. Best fidelity, but ~300MB Chromium dependency.
- **Option B: PDFKit** — Pure JS, no Chromium. More work to lay out, but lightweight. ~2MB dependency.
- **Option C: @react-pdf/renderer** — JSX templates for PDFs. Good balance if we build a web UI.

**Recommendation:** Option A (Puppeteer) for V1. We already have `generateHTMLReport()` — just pipe it through `page.pdf()`. The 300MB dependency is only needed at report-generation time, not during scanning. CLI flag: `--format pdf`.

**Effort:** ~1-2 days.

```typescript
// src/report/pdf-generator.ts
import puppeteer from 'puppeteer';
import { generateHTMLReport } from './generator.js';

export async function generatePDFReport(findings, options): Promise<Buffer> {
  const html = await generateHTMLReport(findings, options);
  const browser = await puppeteer.launch({ headless: true });
  const page = await browser.newPage();
  await page.setContent(html, { waitUntil: 'networkidle0' });
  const pdf = await page.pdf({
    format: 'A4',
    printBackground: true,
    margin: { top: '20mm', bottom: '20mm', left: '15mm', right: '15mm' },
  });
  await browser.close();
  return pdf;
}
```

### TIER 2 — Competitive Parity

#### 3.4 Stack-Specific Checks

**What CheckVibe has:** Convex, Firebase, Supabase, Vercel, Netlify, Cloudflare, GitHub.

**How to build it:**
- Extend our static regex patterns (already have Supabase, NEXT_PUBLIC_)
- Add new pattern groups:
  - **Firebase:** Missing Firestore rules, exposed Admin SDK JSON, insecure `firebase.initializeApp()` config
  - **Vercel/Netlify:** `_headers`/`netlify.toml` analysis, `vercel.json` config checks
  - **Cloudflare:** Worker secrets, Pages config
  - **Stripe:** Live mode keys, webhook secrets
  - **Convex:** `convex/` directory misconfig

**Effort:** ~3-4 days. Most are regex patterns + rule definitions.

#### 3.5 Dashboard / Web UI

**What it does:** Web interface for scanning, viewing reports, managing projects.

**How to build it:**
- Next.js app with:
  - URL input → scan → results page
  - File upload / GitHub OAuth for source code scanning
  - Report viewer with PDF export
  - Project management (multiple scans per project)
- Uses our existing scanner as the backend (API routes call the CLI)

**Effort:** ~1-2 weeks for MVP.

**Decision:** Defer to Phase 3. CLI + MCP is enough for V1. The consultant workflow is: scan via CLI → generate PDF → deliver to client. They don't need a dashboard.

### TIER 3 — Differentiation (Our Moat)

These are things CheckVibe and ALL competitors lack. This is where AttestLens wins.

#### 3.6 APP/NDB Compliance Mapping (✅ Already Built)

Our mapping engine maps technical findings → APP sub-obligations → NDB sections. No competitor does this.

**Enhancement:** Add confidence-weighted mappings to the PDF report. Show "APP 11.1 — Data Storage (85% confidence)" etc.

#### 3.7 Compliance Questionnaire (Shipped in M2)

Interactive questionnaire that fills gaps the scanner can't detect (policies, procedures, training). This transforms AttestLens from a scanner into an **assessment tool**.

#### 3.8 NDB Breach Readiness Score (Shipped in M2)

Aggregate findings + questionnaire answers into a single "breach readiness" score. Consultants can present this to boards.

#### 3.9 Consultant Workflow Features (Partially Shipped)

- Consultant-facing deterministic report narratives
- Breach-readiness score and confidence model
- Finding acknowledgment tracking (client confirms fixes)
- Re-scan diff (what changed between scans)
- White-label PDF reports (consultant branding)

---

## 4. Implementation Roadmap

### Phase 1.5 — Close the CheckVibe Gap (2 weeks)

| Week | Feature | Effort | Impact |
|---|---|---|---|
| W1 D1-2 | **URL Scanner** (`url-scan.ts`) | 2 days | Parity with CheckVibe's core feature |
| W1 D3 | **AI Fix Prompts** (schema + templates) | 1 day | Copy-paste fixes (CheckVibe's #2 feature) |
| W1 D4-5 | **PDF Reports** (Puppeteer pipeline) | 1.5 days | Consultant deliverable |
| W2 D1-3 | **Stack-Specific Checks** (Firebase, Vercel, Stripe, etc.) | 3 days | Competitive parity |
| W2 D4 | **MCP: Add URL scan tool** | 0.5 day | MCP parity with CheckVibe |
| W2 D5 | **Integration tests + docs** | 1 day | Ship readiness |

**Total: ~10 working days**

### Phase 2 — Compliance Differentiation (existing plan)

- Questionnaire engine
- Confidence-weighted mappings
- Breach readiness score
- Enhanced PDF with statutory references

### Phase 3 — Platform (future)

- Web dashboard (Next.js)
- GitHub OAuth integration
- Project management
- Daily monitoring (cron-based re-scans)

---

## 5. GuardVibe Dependency Analysis

**Current state:** AttestLens does NOT depend on GuardVibe. Here's how it actually works:

```
ScannerOrchestrator
  ├── GuardVibeAdapter
  │   ├── Tries: npx @guardvibe/cli full_audit → 335 rules
  │   └── Fallback: 9 static regex patterns → limited but functional
  ├── McpScanAdapter (independent)
  └── SupplyChainAdapter (independent, 9 static rules + dynamic OSV findings)
```

**The problem:** Without GuardVibe CLI installed, we only have 9 regex patterns. CheckVibe has 100+. That's a huge gap.

**The solution:** Don't rely on GuardVibe. Build our own scanner rules directly. The `url-scan.ts` adapter and expanded static patterns in `guardvibe.ts` give us 30+ checks without any external dependency.

**After Phase 1.5:** We'll have:
- 30+ static code patterns (expanded guardvibe.ts)
- 30+ URL/header checks (url-scan.ts)
- 9 supply chain rules plus OSV.dev vulnerability enrichment (supply-chain.ts)
- **= 68+ checks, zero external dependencies**

---

## 6. Competitive Positioning

### Our Position: "CheckVibe meets Australian Privacy Act"

**For consultants:**
> "AttestLens is the only scanner that maps security findings to APP/NDB obligations and generates consultant-grade compliance reports. Scan code or live URLs, get AI fix prompts, and deliver PDF reports your clients can actually use."

**For indie devs (CheckVibe's market):**
> "Free, open-source alternative to CheckVibe. Same security checks, same AI fix prompts, plus Australian compliance mapping. Run locally or via MCP."

### Pricing Strategy (when we add SaaS)

| Tier | Price | Features |
|---|---|---|
| **Free** | $0 | CLI, local scans, JSON/MD/HTML reports, MCP server |
| **Pro** | $15 AUD/mo | URL scanning, PDF reports, AI fix prompts, 50 scans/mo |
| **Consultant** | $49 AUD/mo | White-label PDFs, compliance mapping, breach readiness, unlimited scans, priority support |
| **Enterprise** | Custom | Self-hosted, SSO, API access, SLA |

Free tier = AttestLens CLI (current + Phase 1.5). Pro = SaaS wrapper. Consultant = our moat.

---

## 7. Key Risks

1. **Market saturation:** 15+ vibe-coding scanners exist. But NONE have compliance mapping. Our moat is real.
2. **CheckVibe is SaaS-first:** They own the "paste URL, get results" UX. We need to match this in Phase 1.5 or we look inferior.
3. **GuardVibe stagnation:** If GuardVibe stops updating, our static patterns become stale. Building our own rules solves this.
4. **Australian market size:** ~2.6M businesses, ~9K APP-bound entities. Compliance scanner niche is smaller than general security scanning. But consultants serve thousands of clients each.
5. **Open source vs SaaS tension:** Free CLI means no moat on scanning. Compliance mapping + consultant features are the paywall.

---

## 8. Conclusion

**CheckVibe validated the market** — £13/mo for URL scanning, 500+ devs, $1k/mo revenue at launch. The demand is real.

**Our move:** Close the scanning gap in 2 weeks (URL scanner + AI fix prompts + PDF + stack checks), then double down on compliance mapping — the one thing nobody else has. That's our path from "another vibe-coding scanner" to "the Australian compliance scanner."

Priority order: **URL scanner > AI fix prompts > PDF > stack-specific checks > MCP URL tool > questionnaire**

---

## 9. Shannon (Keygraph) — Deep Dive

**Added:** 2026-04-19
**Repo:** <https://github.com/KeygraphHQ/shannon>
**Sample report:** <https://github.com/KeygraphHQ/shannon/blob/main/sample-reports/shannon-report-juice-shop.md>

### What Shannon Does

Autonomous, white-box AI pentester for web apps and APIs:
1. **Source code analysis** — reads repo to identify attack vectors
2. **Live exploitation** — runs real attacks (SQLi, XSS, SSRF, auth bypass, NoSQL injection, XXE) against the running app using browser automation + CLI tools (Nmap, Subfinder, WhatWeb, Schemathesis)
3. **Proof-of-Concept only** — only reports vulnerabilities with working exploits. No theoretical findings.
4. **Report generation** — structured report with curl-ready PoC commands

### Shannon Lite vs Pro

| | Shannon Lite | Shannon Pro |
|---|---|---|
| License | AGPL-3.0 | Commercial |
| Static Analysis | Code review prompting | Full agentic SAST, SCA, secrets, business logic (CPG-based) |
| Dynamic Testing | Autonomous AI pentesting | + static-dynamic correlation |
| CI/CD | Manual/CLI | Native CI/CD, GitHub PR scanning |
| Deployment | CLI + Docker | Managed cloud or self-hosted runner |

### Shannon's Report Format (Benchmark)

Their Juice Shop report is the gold standard for security report quality:
- **Vulnerability location** (endpoint + HTTP method)
- **Overview** (1-2 sentence explanation)
- **Impact** (business consequence)
- **Severity** (Critical/High/Medium)
- **Prerequisites** (auth needed? public endpoint?)
- **Exploitation Steps** (copy-paste curl commands)
- **Proof of Impact** (actual exfiltrated data shown)
- **Notes** (root cause, source code reference)

→ **Our PDF attestation reports must match this quality bar** on the compliance axis.

### What Shannon Does NOT Do

- ❌ No compliance mapping (APP, NDB, GDPR — nothing)
- ❌ No questionnaire-based assessment
- ❌ No attestation artifacts
- ❌ No evidence of remediation tracking
- ❌ No drift detection or re-attestation
- ❌ No white-label / agency features

### AttestLens vs Shannon Positioning

| | Shannon | AttestLens |
|---|---|---|
| **Core job** | Find + prove exploitable vulns | Map findings → APP/NDB + generate attestation evidence |
| **Output** | Security report with PoCs | Compliance attestation with remediation |
| **Buyer** | Security teams, AppSec | Agencies, MSPs, compliance officers |
| **Regulatory** | None | AU Privacy Act / NDB |
| **Distribution** | CLI + Docker + npx | MCP + CLI + per-stack pages |
| **Moat** | CPG + exploit validation | Evidence graph + attestation chain + APP/NDB mapping |

**Key insight:** Shannon and AttestLens are **complementary**, not competitive. Shannon finds the holes; AttestLens maps them to legal obligations and generates the compliance paper trail. A smart agency runs Shannon for security findings, then feeds those into AttestLens for the attestation pack.

### What We Can Borrow

1. **Report structure** — their finding format (location → overview → impact → severity → steps → proof → notes) is the template our compliance PDF should follow, with APP/NDB clauses added
2. **Open-core model** — Lite (AGPL) + Pro (commercial) validates our MCP-first + paid report approach
3. **"Vibe coding security" positioning** — same narrative. We should reframe as "vibe coding **compliance** risk"
4. **PoC-style remediation** — their curl-ready exploits → our AI fix prompts should be equally copy-paste ready
5. **Sample report as marketing** — their public Juice Shop report is a conversion tool. We should publish a sample attestation report for a well-known AU app.

### Integration Opportunity: Shannon → AttestLens Adapter

See `docs/SHANNON-ADAPTER-SPEC.md` for the deferred research note and future design constraints.

**Important:** Shannon integration is exploratory and explicitly out of scope for the current shipped roadmap. It should not widen current CLI, MCP, or schema contracts until future prioritization and a full trust-boundary design are approved.

**Core idea:** Import Shannon scan results (JSON) → auto-map findings to APP/NDB → generate compliance attestation pack. "From pentest to attestation in 5 minutes."

---

## 10. Pentest-Swarm-AI (Armur) — Deep Dive

**Added:** 2026-04-20
**Repo:** <https://github.com/Armur-Ai/Pentest-Swarm-AI>

### What Pentest-Swarm-AI Does

Autonomous pentester using a **stigmergic swarm** architecture (not a pipeline):

- **Stigmergy** — agents coordinate by reading/writing findings on a shared blackboard (Postgres + pgvector). Pheromone weights bias agents toward promising attack paths; weights decay over time so stale paths die.
- **Emergence** — attack chains emerge from blackboard state, not a central planner. Recon finding wakes classifier → high-severity wakes exploit agent → exploit results feed back and wake report agent.
- **Decentralization** — each agent has its own trigger predicate. Add a new agent and it joins without rewiring.

4 agent types: Recon (8 ProjectDiscovery tools), Classify (CVE mapping + CVSS scoring), Exploit (attack chain builder), Report (MD/HTML/JSON/SARIF output).

Uses Claude API. Runs via `brew`, `docker`, or `go install`.

### Feature Status

| Feature | Status |
|---|---|
| Sequential 5-phase runner | Stable |
| Stigmergic swarm scheduler | Alpha |
| ProjectDiscovery toolchain | Stable |
| MCP server | Beta |
| VS Code extension | Beta |
| GitHub Action (SARIF) | Beta |
| Live dashboard | Alpha |
| Burp MCP / Metasploit / ZAP adapters | Planned |

### Their Competitive Table (Our Intel)

Pentest-Swarm's own comparison table maps the AI pentester landscape:

| Tool | Architecture | Executes? | Memory | MCP | Swarm? |
|---|---|---|---|---|---|
| Pentest-Swarm-AI | Stigmergic blackboard | ✅ | pgvector + pheromones | ✅ | ✅ real |
| Shannon | White-box + browser | ✅ | Session state | ❌ | Pipeline |
| PentAGI | 4 agents + planner | ✅ | pgvector | Partial | Pipeline |
| PentestGPT | Single-agent ReAct | Suggests | None | ❌ | No |
| HexStrike | MCP tool wrapper | Delegates | Stateless | ✅ | No |
| Pentest-R1 | RL-tuned LLM | ✅ | Trajectory | ❌ | No |
| HackingBuddyGPT | Single-agent | ✅ | Run logs | ❌ | No |

This is useful market intel — confirms Shannon, PentAGI, and HexStrike as the serious pentest tools, and PentestGPT as suggestion-only.

### What Pentest-Swarm Does NOT Do

- ❌ No compliance mapping (APP, NDB, GDPR — nothing)
- ❌ No questionnaire-based assessment
- ❌ No attestation artifacts
- ❌ No evidence of remediation tracking

Same gap as every other pentest tool. AttestLens's lane.

### Relevance to AttestLens

1. **MCP distribution validates our approach** — Another security tool going MCP-first. The developer tooling channel is converging on MCP.

2. **SARIF output is a promising transport format** — Pentest-Swarm outputs SARIF, which is an industry standard (OASIS) for static analysis results. This is a useful research direction for future import work:
   - SARIF is supported by: Semgrep, CodeQL, SonarQube, GitHub Code Scanning, Snyk, Checkmarx, and now Pentest-Swarm
   - A SARIF importer could eventually give us findings from many tools through one intake format
   - This may be a better long-term direction than maintaining many per-tool adapters, but it does **not** remove the need for trust-boundary controls, source-specific validation, and evidence isolation
   - Recommendation: treat SARIF as a **preferred research direction** for post-M2 import work, not as an approved roadmap pivot or live interface change

3. **Apache 2.0 license** — More permissive than Shannon's AGPL-3.0. If we ever embed any reference logic, Apache is safe. AGPL is not.

4. **Pheromone/decay concept** — Interesting but not directly applicable to compliance. What IS applicable: the idea that findings have **weight/confidence** that can change over time. Our mapping engine already uses confidence scores.

### AttestLens vs Pentest-Swarm Positioning

| | Pentest-Swarm-AI | AttestLens |
|---|---|---|
| **Core job** | Find + exploit vulns via swarm | Map findings → APP/NDB + generate attestation |
| **Output** | Security report (SARIF/MD/HTML) | Compliance attestation (PDF) |
| **Buyer** | Security teams, bug bounty hunters | Agencies, MSPs, compliance officers |
| **Regulatory** | None | AU Privacy Act / NDB |
| **Distribution** | CLI + Docker + MCP | MCP + CLI + per-stack pages |
| **Moat** | Swarm architecture + pheromones | Evidence graph + attestation chain + APP/NDB mapping |

**Same conclusion as Shannon:** Complementary, not competitive. Agencies could run Pentest-Swarm for finding vulns, then import SARIF into AttestLens for the compliance pack.

---

## 11. Research Direction: SARIF as a Preferred Import Transport

**Added:** 2026-04-20

### Why SARIF Over Per-Tool Adapters

The original Shannon adapter spec proposed a `PentestImport` schema with per-tool parsers. That works but doesn't scale — every new pentest tool needs a new adapter.

SARIF (Static Analysis Results Interchange Format) is an OASIS standard with wide adoption:

| Tool | SARIF Support |
|---|---|
| **Pentest-Swarm-AI** | ✅ Native output |
| **Semgrep** | ✅ Native output |
| **CodeQL** | ✅ Native output |
| **GitHub Code Scanning** | ✅ Native input/output |
| **SonarQube** | ✅ Export |
| **Snyk** | ✅ Via `snyk sarif` |
| **Checkmarx** | ✅ Export |
| **Shannon** | ❌ (JSON only — would need a converter) |

### Proposed Research Architecture

```
┌─────────────────┐     ┌──────────────────────┐     ┌──────────────────────┐
│  Any SARIF Tool │────▶│   Raw Intake         │────▶│ Quarantine /         │
│  (Semgrep,      │     │   + Producer Check   │     │ Validation           │
│   Pentest-Swarm,│     └──────────────────────┘     └──────────┬───────────┘
│   CodeQL, etc.) │                                            │
└─────────────────┘                                            ▼
                                                       ┌──────────────────────┐
                                                       │ Sanitized            │
                                                       │ Normalization        │
                                                       │ (+ optional Shannon  │
                                                       │  JSON research       │
                                                       │  converter)          │
                                                       └──────────┬───────────┘
                                                                  │
                                                                  ▼
                                                       ┌──────────────────────┐
                                                       │ Mapping Engine       │
                                                       │ + Finding Merge      │
                                                       └──────────┬───────────┘
                                                                  │
                                                                  ▼
                                                       ┌──────────────────────┐
                                                       │ Report / Evidence    │
                                                       │ Rendering            │
                                                       └──────────────────────┘
```

Important guardrails for this research direction:

- SARIF is a **transport/input format**, not a trust signal
- imported third-party evidence is **untrusted and sensitive by default**
- raw imported evidence must never flow directly into normal PDF/HTML/Markdown reports or public MCP payloads
- if raw evidence is retained at all, it must stay in a separate raw-evidence or evidence-bundle path with stricter access controls
- this section does **not** approve any live `ScanSource`, CLI, MCP, or report-schema changes; any future provenance fields remain internal research placeholders until a separate post-M2 design is approved

### SARIF → APP/NDB Mapping Hints

SARIF may expose tags and metadata that help drive a first-pass classification, but these are **advisory metadata**, not guaranteed identifiers. Producer and version variation should be expected.

| SARIF `rule.properties.tags` | APP/NDB Mapping |
|---|---|
| `security`, `injection` | APP 11.1, NDB |
| `authentication` | APP 11.1, APP 6 |
| `authorization`, `access-control` | APP 6, APP 11.1 |
| `xss` | APP 11.1, NDB |
| `secrets`, `credential` | APP 11.1, NDB |
| `misconfiguration` | APP 11.1 |
| `ssrf` | APP 11.1, APP 8 |
| `info-disclosure` | APP 11.1, APP 6 |

### Implementation Notes

- Validate SARIF schema version (2.1.0 is current OASIS standard)
- Validate producer/tool identity when possible (for example `run.tool.driver.name`), but do not trust it blindly
- Treat `result.level`, `rule.properties.tags`, `result.ruleId`, and `result.locations` as advisory metadata that may be absent, weak, or producer-specific
- Require fallback classification when tags, rule IDs, or locations are missing or too weak for confident mapping
- Confidence-score all imported findings lower than native AttestLens findings (imported = secondary evidence)
- Keep a raw intake copy for audit/debug instead of trusting only the normalized shape
- Any future provenance metadata should remain internal research placeholders until a separate post-M2 import contract is approved

This remains a **deferred research direction** pending M2 completion and design-partner validation.
