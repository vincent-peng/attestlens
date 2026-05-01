# Clearway by AttestLens

<p><strong>Logo placeholder: Clearway by AttestLens</strong></p>

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](#license)
[![MCP compatible](https://img.shields.io/badge/MCP-compatible-0f766e.svg)](#mcp-integration)

Clearway — Privacy Compliance Deploy Gate for AI Agents. Multi-jurisdiction privacy checks for AU Privacy Act, US CCPA/CPRA, EU GDPR subset, and SG PDPA beta coverage.

## Beta Notice

This is an early public beta. The CLI, MCP surface, and jurisdiction coverage are usable now, but interfaces may still evolve as design partners validate report shape, workflow fit, and pack coverage.

Install the beta explicitly:

```bash
npm install -g @attestlens/cli@beta
npx @attestlens/cli@beta scan ./my-project
```

## The Problem

AI agents can ship privacy violations faster than humans can review them. Teams need a privacy deploy gate that runs before code reaches production, works in CI, and gives agents structured actions instead of loose legal notes.

Clearway scans codebases and URLs, maps findings to supported jurisdiction obligations, and produces structured compliance outputs that agents can use directly in CI, MCP clients, and remediation workflows.

## Quick Start

```bash
npx @attestlens/cli@beta scan ./my-project
npx @attestlens/cli@beta scan https://example.com
```

AU Privacy Act remains the default for backward compatibility:

```bash
npx @attestlens/cli@beta audit ./my-project --opinion --format agent
```

Run the same project under different jurisdictions:

```bash
npx @attestlens/cli@beta audit ./my-project --jurisdiction au-privacy-act --opinion --format agent
npx @attestlens/cli@beta audit ./my-project --jurisdiction us-ccpa --opinion --format agent
npx @attestlens/cli@beta audit ./my-project --jurisdiction eu-gdpr --opinion --format agent
npx @attestlens/cli@beta audit ./my-project --jurisdiction sg-pdpa --opinion --format agent
```

For the multi-jurisdiction demo:

```bash
bash demo/multi-jurisdiction.sh
```

## Features

| User benefit | What Clearway provides |
| --- | --- |
| Privacy deploy gate for AI agents | A CLI and MCP server built to block risky releases before deploy, not just generate advisory notes after the fact. |
| Multi-jurisdiction privacy checks | Jurisdiction packs for AU Privacy Act, US CCPA/CPRA, EU GDPR subset, and SG PDPA beta coverage, selected with `--jurisdiction`. |
| Compliance opinions | Structured verdicts and evidence tied to jurisdiction obligations for downstream agent workflows and human review. |
| AI agent integration | MCP tools for project scans, URL scans, full audits, regulation mapping, opinions, principle checks, SMB compliance checks, and reform assessments. |
| SMB compliance workflow | Plain-English questions and reports for Australian small and medium businesses. |
| Reform readiness | Automated remediation suggestions for Privacy Act reform exposure, including action items and priority warnings. |
| Agent-native output | `--format agent` produces compact JSON designed for agent consumption, CI summaries, and follow-up task generation. |
| Rule authoring pipeline | `propose-rules` and `review-pack` support AI-assisted drafting with human approval gates. |

## MCP Integration

Clearway can run as a Model Context Protocol server for Claude, Cursor, or any MCP-compatible client.

Add this server to your MCP client configuration:

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

Available MCP tools:

| Tool | Purpose |
| --- | --- |
| `attestlens_scan` | Scan a local project and return findings for the selected jurisdiction. |
| `attestlens_scan_url` | Scan a public URL and return live-site findings for the selected jurisdiction. |
| `attestlens_audit` | Run a full audit and return a jurisdiction-specific compliance report. |
| `attestlens_map` | Map supplied findings to supported jurisdiction obligations. |
| `attestlens_opinion` | Generate a compliance opinion for the selected jurisdiction. |
| `attestlens_check` | Check one regulation principle and return the relevant result. |
| `attestlens_compliance_check` | Run the AU-only SMB compliance-check workflow. |
| `attestlens_reform` | Assess AU Privacy Act reform exposure and remediation needs. |

MCP tools that scan paths accept `jurisdiction` where multi-jurisdiction behavior is supported:

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
| `scan` | `npx @attestlens/cli@beta scan ./my-project --jurisdiction eu-gdpr` | Run a fast project or URL assessment. |
| `audit` | `npx @attestlens/cli@beta audit ./my-project -n "My Business" --jurisdiction us-ccpa` | Produce a full jurisdiction-specific compliance report. |
| `attest` | `npx @attestlens/cli@beta attest ./my-project --jurisdiction eu-gdpr` | Start or resume a questionnaire-backed attestation session. |
| `install` | `npx @attestlens/cli@beta install --client claude-code` | Configure supported MCP clients. |
| `uninstall` | `npx @attestlens/cli@beta uninstall --client claude-code` | Remove generated client configuration. |
| `mcp` | `npx @attestlens/cli@beta mcp` | Launch the MCP server over stdio. |
| `propose-rules` | `npx @attestlens/cli@beta propose-rules --help` | Draft new rule candidates for review. |
| `review-pack` | `npx @attestlens/cli@beta review-pack --help` | Review and approve authored rule packs. |

Common report formats:

```bash
npx @attestlens/cli@beta audit ./my-project --format html,json,markdown,pdf
npx @attestlens/cli@beta audit ./my-project --format agent --opinion
```

Useful assessment flags:

```bash
npx @attestlens/cli@beta scan ./my-project --jurisdiction us-ccpa
npx @attestlens/cli@beta scan ./my-project --external-enrichment
npx @attestlens/cli@beta scan ./my-project --scanner-timeout 60000
npx @attestlens/cli@beta audit ./my-project --strict
```

Supported jurisdiction values:

```text
au-privacy-act
us-ccpa
eu-gdpr
sg-pdpa
```

## Architecture

Clearway separates collection, mapping, opinion, and reporting:

1. Scanner adapters collect project, URL, MCP, supply-chain, behavioral, and infrastructure evidence.
2. Jurisdiction packs define supported principles, rule metadata, citations, and jurisdiction-specific scanner checks.
3. The mapping engine links findings to AU APP/NDB, US CCPA/CPRA, EU GDPR, or SG PDPA obligations.
4. The opinion engine produces structured compliance opinions from findings and questionnaire evidence.
5. Report writers produce human-readable, JSON, PDF, SARIF, and agent-native formats.
6. The MCP server exposes the same assessment model through structured Zod schemas.

Current jurisdiction coverage is multi-jurisdiction, not global. AU, US, and EU packs are live. SG PDPA is included as beta coverage and should still be presented conservatively until it has external legal validation.

## Contributing

Read the project docs before changing scanner, report, or MCP behavior:

- [Status](docs/STATUS.md)
- [Roadmap](docs/ROADMAP.md)
- [Validation runbook](docs/validation/ATTESTATION-RUNBOOK.md)

## License

MIT
