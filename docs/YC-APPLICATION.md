# YC Application Draft

## One-Liner

Deterministic compliance runtime for AI agents.

## What You're Building

Clearway is the compliance check that runs before AI agents ship code. It scans codebases and URLs for privacy law violations across multiple jurisdictions (AU, US, EU), producing deterministic compliance opinions: not findings to interpret, but verdicts to act on. Agents call Clearway via MCP before deploying; CI pipelines gate on compliance verdicts. Same engine, three jurisdictions, zero LLM calls.

## Progress

8 phases shipped in 4 weeks. 502 tests, zero LLM dependency. MCP server with 8 tools and structured Zod schemas. Three jurisdiction packs (AU Privacy Act, US CCPA/CPRA, EU GDPR subset) producing different citations and outcomes from the same codebase. Deterministic opinion engine: same input always produces the same verdict. Fail-closed security: symlink blocking, DNS pinning, TOCTOU revalidation. Running as CLI and MCP server today.

## How You'll Make Money

Free tier for agents and indie devs: local scans and 3 core tools. Pro tier for teams: $29/mo for opinion engine, all 8 tools, and multi-jurisdiction coverage. Enterprise for organizations that need custom compliance reporting, SSO, SLA, procurement support, or custom jurisdiction workflows. The free tier is the wedge: every coding agent runs Clearway in CI, and teams upgrade for opinion-grade verdicts and multi-jurisdiction coverage.

## Why This Team

Building in Australia, the strictest privacy reform market in 2024. Deep experience with privacy compliance from the founder side: not consulting, not auditing, but shipping software that has to comply. We built the compliance tool we wished we had.

## Why Now

July 2026: 100K+ Australian SMBs fall under Privacy Act obligations for the first time. December 2026: automated decision-making transparency requirements kick in. In the US, CCPA enforcement is escalating. In the EU, GDPR enforcement is maturing. AI agents are deploying privacy violations at machine speed. The compliance check needs to run before the agent ships, not after the regulator inquires.

## Why YC

Three of YC's 2026 RFS categories map directly to what we've already built: AI-Native Service Companies (compliance as a service), Software for Agents (MCP-native compliance), and Company Brain (compliance memory). We're not pivoting to fit the RFS; we were already building this.

## Supporting Proof Points

- CLI package: `@attestlens/cli`
- MCP server: `attestlens-mcp`
- Current baseline: v0.3.0, 3 jurisdiction packs, 8 MCP tools, 502 tests, `tsc --noEmit` clean
- Jurisdictions: AU Privacy Act, US CCPA/CPRA, EU GDPR subset
- Core claim: multi-jurisdiction, not global
