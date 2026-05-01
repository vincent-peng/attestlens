# YC Application Draft

**Last Updated:** 2026-05-01
**Status:** Draft — needs Phase 10-lite + design partner validation before submission

---

## One-Liner

The deploy gate for AI privacy risk.

## What You're Building

Clearway is the compliance check that blocks deploys when AI agents ship privacy violations. It scans codebases and URLs for jurisdiction-specific privacy law violations (AU Privacy Act, US CCPA, EU GDPR), producing deterministic compliance opinions — not findings to interpret, but verdicts to act on. Agents call Clearway via MCP before merging; CI pipelines gate on high-confidence verdicts. Same engine, three jurisdictions, zero LLM at runtime.

**What this means:** When an AI coding agent submits a PR that adds a new API endpoint leaking personal data to logs, Clearway blocks the merge with: "FAIL — APP 11.1 Security of Personal Information — confidence: HIGH — remediation: remove PII from log output." That's not a suggestion. That's a gate.

## Progress

9 phases shipped in 4 weeks. 504 tests, zero LLM dependency. MCP server with 8 tools and structured Zod schemas. Three jurisdiction packs producing different citations and outcomes from the same codebase. Deterministic opinion engine: same input always produces the same verdict. Fail-closed security: symlink blocking, DNS pinning, TOCTOU revalidation. Running as CLI and MCP server today. GitHub Action + MCP agent recipes in progress.

## How You'll Make Money

Free tier is the agent adoption wedge: every coding agent runs Clearway via MCP, unlimited scans, 1 repo. Pro tier ($99-199/mo per 5 protected repos) for teams who need CI deploy gating, opinion-grade verdicts, and evidence retention. Enterprise ($15-50K+/yr) for orgs that need self-hosted, SSO, custom jurisdiction packs, and governance integrations.

We don't meter scans or agent calls — more compliance checking = more value, not more billing fear.

## Why This Team

Building in Australia, the strictest privacy reform market in 2024. Deep experience with privacy compliance from the founder side: not consulting, not auditing, but shipping software that has to comply. We built the compliance tool we wished we had.

## Why Now

July 2026: Australian SMBs fall under expanded Privacy Act obligations. December 2026: automated decision-making transparency requirements kick in. In the US, CCPA enforcement is escalating. In the EU, GDPR enforcement is maturing. AI agents are deploying privacy violations at machine speed. The compliance check needs to run before the agent ships, not after the regulator inquires.

## Why YC

Three of YC's 2026 RFS categories map directly: AI-Native Service Companies (compliance as a service), Software for Agents (MCP-native compliance gates), and Company Brain (compliance memory). We're not pivoting to fit the RFS; we were already building this.

## Competitors

HoundDog.ai (PII taint tracking, $3.1M seed) and Privado.ai (governance platform, $17.5M Series A) detect privacy issues in code. Clearway is different: we produce jurisdiction-cited deploy-gate verdicts that can block a CI pipeline, we run fully offline with zero cloud dependency, and we're the only product mapping the Australian Privacy Act. Detect ≠ Gate.