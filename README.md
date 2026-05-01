# Clearway

**Privacy compliance deploy gate for AI agents.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](#license)
[![MCP compatible](https://img.shields.io/badge/MCP-compatible-0f766e.svg)](#mcp-integration)

> AI agents can now execute multi-step cyber operations autonomously. When agents act at machine speed, you need compliance gates that match. Clearway is that gate — deterministic, offline, MCP-native.

## Why This Exists

Frontier models are automating cyber tasks. Agents are making deploy decisions. The internet is being rebuilt for agents as first-class citizens (Altman), and every agent action is a potential privacy violation.

**$50M+ fines. 100K+ businesses newly liable. Agents shipping violations at machine speed.**

You need a compliance checkpoint that's as fast as the agents themselves. Not a PDF report for the CISO — a deploy gate that blocks before violations ship.

Clearway scans codebases and URLs, maps findings to jurisdiction obligations, and produces structured compliance verdicts that agents use directly in CI pipelines, MCP clients, and remediation workflows.

**Zero LLM at runtime.** Fully deterministic. Fully offline.

## Quick Start

```bash
npx @attestlens/cli@beta scan ./my-project
npx @attestlens/cli@beta scan https://example.com
```

Get a compliance opinion — the agent-native verdict:

```bash
npx @attestlens/cli@beta audit ./my-project --opinion --format agent
```

Multi-jurisdiction checks:

```bash
npx @attestlens/cli@beta audit ./my-project --jurisdiction au-privacy-act --opinion --format agent
npx @attestlens/cli@beta audit ./my-project --jurisdiction us-ccpa --opinion --format agent
npx @attestlens/cli@beta audit ./my-project --jurisdiction eu-gdpr --opinion --format agent
npx @attestlens/cli@beta audit ./my-project --jurisdiction sg-pdpa --opinion --format agent
```

## What Clearway Does

- **Deploy gate, not advisory** — Blocks risky releases before they ship. Exit codes and SARIF for CI integration.
- **Multi-jurisdiction** — AU Privacy Act (68+ rules), US CCPA/CPRA, EU GDPR subset, SG PDPA beta. Same scan, different citations.
- **Compliance opinions** — Structured verdicts with evidence tied to jurisdiction obligations. Agents can act on them directly.
- **MCP-native** — 8 MCP tools for Claude, Cursor, any MCP client. First-class agent integration.
- **Deterministic runtime** — Zero LLM, zero network at scan time. Fully offline, fully reproducible.
- **Agent-native output** — `--format agent` produces compact JSON for agent consumption in CI and task workflows.
- **SMB compliance** — Plain-English questions and reports for Australian small and medium businesses.
- **Rule authoring** — AI-assisted rule drafting with human approval gates. Rules scale without hardcoding.

## MCP Integration

Add to your MCP client config:

```json
{
  "mcpServers": {
    "clearway": {
      "command": "npx",
      "args": [
        "-y",
        "--package",
        "@attestlens/cli@beta",
        "attestlens-mcp"
      ]
    }
  }
}
```

**8 MCP tools:**

| Tool | Purpose |
| --- | --- |
| `attestlens_scan` | Scan a local project for the selected jurisdiction |
| `attestlens_scan_url` | Scan a public URL for live-site findings |
| `attestlens_audit` | Full audit with jurisdiction-specific compliance report |
| `attestlens_map` | Map findings to jurisdiction obligations |
| `attestlens_opinion` | Generate a structured compliance opinion |
| `attestlens_check` | Check one regulation principle |
| `attestlens_compliance_check` | AU SMB compliance-check workflow |
| `attestlens_reform` | AU Privacy Act reform exposure assessment |

Pass `jurisdiction` to any scan tool:

```json
{
  "path": "./my-project",
  "jurisdiction": "us-ccpa",
  "opinion": true,
  "format": "agent"
}
```

## CLI Reference

| Command | Example | Purpose |
| --- | --- | --- |
| `scan` | `npx @attestlens/cli@beta scan ./my-project --jurisdiction eu-gdpr` | Fast project or URL assessment |
| `audit` | `npx @attestlens/cli@beta audit ./my-project -n "My Business" --jurisdiction us-ccpa` | Full jurisdiction-specific compliance report |
| `attest` | `npx @attestlens/cli@beta attest ./my-project --jurisdiction eu-gdpr` | Questionnaire-backed attestation session |
| `install` | `npx @attestlens/cli@beta install --client claude-code` | Configure MCP clients |
| `mcp` | `npx @attestlens/cli@beta mcp` | Launch MCP server over stdio |
| `propose-rules` | `npx @attestlens/cli@beta propose-rules --help` | Draft new rule candidates |
| `review-pack` | `npx @attestlens/cli@beta review-pack --help` | Review and approve rule packs |

Report formats:

```bash
npx @attestlens/cli@beta audit ./my-project --format html,json,markdown,pdf,sarif
npx @attestlens/cli@beta audit ./my-project --format agent --opinion
```

Supported jurisdictions: `au-privacy-act` · `us-ccpa` · `eu-gdpr` · `sg-pdpa`

## Architecture

1. **Scanner adapters** collect project, URL, supply-chain, behavioral, and infrastructure evidence
2. **Jurisdiction packs** define principles, rules, citations, and scanner checks per jurisdiction
3. **Mapping engine** links findings to AU APP/NDB, US CCPA/CPRA, EU GDPR, or SG PDPA obligations
4. **Opinion engine** produces structured compliance verdicts from findings + questionnaire evidence
5. **Report writers** produce HTML, JSON, PDF, SARIF, and agent-native formats
6. **MCP server** exposes everything through structured Zod schemas

Deterministic at runtime. No LLM calls. No network dependency. Same input → same output, every time.

## Beta Notice

This is an early public beta. Interfaces may evolve as design partners validate report shape, workflow fit, and pack coverage. Install explicitly:

```bash
npm install -g @attestlens/cli@beta
```

## License

MIT