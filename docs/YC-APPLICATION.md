# YC Application Draft — International Reset

**Company/product:** AttestLens / Clearway  
**Positioning:** Privacy deploy gate for AI-generated software  
**YC direction:** Software for Agents + AI-native service infrastructure + company policy brain  
**Status:** Use this as the YC-facing source of truth. Retire older, broader drafts.

---

## One-liner

Clearway makes AI coding agents comply with privacy law before they merge code.

Alternative one-liners:

- The deterministic privacy deploy gate for agent-written software.
- CI/CD policy gates for AI agents that touch customer data.
- We block AI-generated privacy violations before they ship.

Best YC version:

> Clearway is the deterministic privacy deploy gate for AI-generated software.

---

## What are you building?

AI coding agents can now create routes, log data, add analytics, change dependencies, and modify infrastructure faster than privacy and security teams can review every change. Clearway runs before those changes merge.

It scans a codebase or PR, maps technical evidence to privacy-law obligations, and returns a deterministic deploy verdict that CI systems and MCP-compatible agents can act on: pass, block, or needs human review.

The runtime is deterministic: no LLM calls at scan time. Jurisdiction packs define rules, citations, confidence, coverage boundaries, and validation status. AI can help draft rules, but only human-reviewed rules can become blocking.

We start with privacy-law risk across AU Privacy Act, US CCPA/CPRA, and a GDPR subset. The long-term product is the policy runtime for AI agents: before an agent ships code or takes a production action involving customer data, it must pass an evidence-backed policy gate.

---

## Why now?

The software-development bottleneck is shifting from writing code to trusting agent-created changes. When agents create more PRs and touch more business workflows, companies need fast, deterministic controls that run at machine speed.

Privacy risk is a strong first wedge because:

1. AI features and agents often touch customer or employee data.
2. Manual privacy review does not scale to every AI-generated change.
3. Existing GRC tools are mostly post-hoc systems of record, not pre-merge gates.
4. Security scanners find vulnerabilities, but they usually do not produce privacy-law deploy decisions with jurisdiction-specific citations and policy boundaries.

---

## What is the product today?

Shipped beta:

- TypeScript CLI package: `@attestlens/cli`.
- MCP server with tools for scan, URL scan, audit, map, opinion, single-control check, AU SMB workflow, and AU reform workflow.
- Deterministic scanner runtime.
- SARIF output and CI exit-threshold controls.
- Four jurisdiction packs in varying maturity: AU Privacy Act, US CCPA/CPRA, EU GDPR subset, SG PDPA beta/stub.
- Compliance opinion engine.
- Rule-authoring pipeline where AI drafts candidate rules and a human validates them before runtime use.
- Local/offline-first design.

What is not proven yet:

- Paid customers.
- External legal validation of every non-AU pack.
- Low-false-positive CI deployments in real customer repos.
- Deep PII taint tracking comparable to specialist privacy-code scanners.

This application should be honest about the gap: the product is built enough to test; the next milestone is design-partner validation.

---

## Who are the first customers?

Primary ICP:

> AI-native B2B SaaS companies with international customers, active coding-agent usage, and customer/employee PII in their product.

Specific early targets:

- Seed to Series B SaaS teams using Cursor, Claude Code, Codex, or internal coding agents.
- SaaS companies selling into the US/EU/AU with privacy-review obligations.
- Teams in HR tech, fintech, health tech, edtech, devtools, customer support, and analytics.
- Engineering/security teams willing to run a deploy gate in advisory mode first.

Do not start with banks, government, or large enterprise procurement. Use them later as enterprise validation.

---

## What is the wedge?

The wedge is not “global compliance.” That sounds impossible and legally risky.

The wedge is:

> Run Clearway on AI-generated PRs and block high-confidence privacy-law risks before merge.

First pilot workflow:

1. Install Clearway in a repo.
2. Run in advisory mode on all pull requests.
3. Measure findings, false positives, and privacy-risk deltas.
4. Enable blocking only for high-confidence rules.
5. Add jurisdiction packs relevant to the customer’s markets.

---

## How will you make money?

Start with protected software surfaces, not seats and not per-scan pricing.

- Free: local CLI + MCP, one protected repo, basic packs, no evidence retention.
- Pro: $199/month per 5 protected repos/pipelines, unlimited scans, CI gating, SARIF, agent output, evidence retention, support.
- Enterprise: $15k-$50k/year for self-hosted, SSO, custom packs, private rule validation, and compliance/governance integrations.

Do not meter agent calls in early product. The point is to make agents check frequently.

---

## What is your moat?

The current moat is not “we have regexes.” That is copyable.

The real moat should become:

1. **Validated jurisdiction-pack corpus:** rules, citations, test fixtures, coverage boundaries, and legal-review provenance.
2. **Low-false-positive deploy-gate data:** which rules are safe to block vs advisory in real repos.
3. **Agent workflow integration:** MCP + CI + PR metadata + remediation loops.
4. **Evidence history:** every scan creates a baseline and audit trail of what changed, why it mattered, and how it was remediated.
5. **Policy runtime schema:** a standard way for agents to ask, “Am I allowed to ship this?”

The moat is built through deployment and validation, not just code.

---

## Competitors

Surface-level competitors:

- HoundDog.ai and Privado.ai for privacy-code scanning and privacy governance.
- Semgrep, Snyk, CodeQL, Trivy, Checkov for CI security scanning.
- Vanta, Drata, Secureframe, OneTrust, TrustArc for compliance/GRC workflows.
- Frontier-model security agents for ad hoc code review and remediation.

Clearway is different because it is a deterministic **deploy gate for agent-generated privacy risk**, not a dashboard, not a generic SAST tool, and not a prompt-based auditor.

How to say this in YC:

> HoundDog and Privado help teams discover data-flow/privacy issues. Vanta/Drata help teams manage compliance programs. Clearway sits earlier in the workflow: before an AI-generated change merges, it returns a jurisdiction-specific deploy decision with evidence and citations.

---

## Why international?

The product should not be limited to Australia. But the pitch must not claim global compliance.

The correct framing:

> Clearway is an international policy-pack runtime. AU is the deepest seed pack. US/CCPA and EU/GDPR prove the engine generalizes. Every pack has explicit coverage boundaries and validation status.

International strategy:

- AU: depth and founder-market edge.
- US/California: YC buyer network and commercial urgency.
- EU/GDPR: international credibility and strict privacy expectations.
- Other jurisdictions: add only when design-partner demand justifies them.

---

## What should be in the YC demo?

Demo title:

> Agent writes privacy-risky code. Clearway blocks it before merge.

Demo flow:

1. A coding agent adds a route that logs email/phone/health/payment-like data or adds a risky tracker/SDK.
2. Clearway runs in CI or through MCP.
3. It returns `BLOCK` for AU APP 11 or `NEEDS_REVIEW` for GDPR Art. 6/13/32 depending on pack validation status.
4. It shows evidence, citation, confidence, and remediation.
5. The agent applies the fix.
6. The gate passes.

The “aha” moment is not a PDF report. It is a failed PR check that an agent can understand and fix.

---

## What are the top risks?

1. **No design partners yet.** Mitigation: run a 2-week validation sprint before or alongside YC submission.
2. **Looks like a privacy scanner clone.** Mitigation: demo deploy gating and agent workflow, not dashboards.
3. **Legal accuracy risk.** Mitigation: coverage boundaries, validation status, no legal-advice claims, and no `COMPLIANT` output for unvalidated packs.
4. **False positives.** Mitigation: advisory mode first, high-confidence blocking only, explicit false-positive metrics.
5. **PII tracing gap.** Mitigation: start with high-confidence rules; build “taint-lite” only after pilot evidence.

---

## Current ask from YC

YC should help with:

- Design partner introductions to AI-native SaaS companies.
- Sharpening the wedge from privacy scanner to agent policy runtime.
- Go-to-market for developer/security buyers.
- Hiring or advisor access for privacy/security validation.
- US customer access for CCPA/GDPR pilots.

---

## Stop/pivot criteria

Continue only if customer validation supports the gate.

Stop or pivot if, after 50 targeted design-partner outreaches:

- Fewer than 5 teams agree to a call.
- No team agrees to a shadow-mode scan.
- Findings are mostly generic issues already handled by existing tools.
- Buyers want post-hoc reports but will not install CI/MCP checks.

Pivot direction if needed:

> Evidence-backed privacy/security review service for AI-generated software changes.

Use the same engine, but sell a service first.
