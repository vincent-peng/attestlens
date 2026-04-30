# Clearway by AttestLens

<p><strong>Logo placeholder: Clearway by AttestLens</strong></p>

[![npm version](https://img.shields.io/npm/v/%40attestlens%2Fcli.svg)](https://www.npmjs.com/package/@attestlens/cli)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](#license)
[![MCP compatible](https://img.shields.io/badge/MCP-compatible-0f766e.svg)](#mcp-integration)

Australian Privacy Act compliance service powered by AI, built for instant compliance opinions, agent workflows, and evidence-backed reporting.

## The Problem

Australian businesses need to understand whether their systems meet Privacy Act 1988, Australian Privacy Principles, and Notifiable Data Breaches obligations. The work is complex, manual, and expensive: teams must review source code, live sites, operational controls, breach readiness, and upcoming reform exposure before they can form a defensible view.

Clearway makes that first compliance opinion instant. It combines deterministic assessment logic, structured evidence, plain-English reporting, and MCP integration so teams and AI agents can move from project or URL to compliance position without a manual first pass.

## Quick Start

```bash
npx @attestlens/cli scan ./my-project
npx @attestlens/cli scan https://example.com
```

For a full report:

```bash
npx @attestlens/cli audit ./my-project --opinion --format html,json,agent
npx @attestlens/cli compliance-check ./my-project
```

## Features

| User benefit | What Clearway provides |
| --- | --- |
| Instant compliance opinions | Deterministic opinion bands: `NOT_COMPLIANT`, `NEEDS_REVIEW`, or `COMPLIANT`, with evidence tied to Privacy Act obligations. |
| AI agent integration | 8 MCP tools for project scans, URL scans, full audits, APP/NDB mapping, opinions, single-principle checks, SMB compliance checks, and reform assessments. |
| SMB compliance workflow | 15 plain-English questions that produce a plain-English compliance report for Australian small and medium businesses. |
| Reform readiness | Automated remediation suggestions for Privacy Act reform exposure, including action items and priority warnings. |
| Agent-native output | `--format agent` produces compact JSON designed for agent consumption, CI summaries, and follow-up task generation. |
| Structured responses | MCP tools return structured content validated by Zod schemas, not loose text blobs. |

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
        "@attestlens/cli",
        "attestlens-mcp"
      ]
    }
  }
}
```

Available MCP tools:

| Tool | Purpose |
| --- | --- |
| `attestlens_scan` | Scan a local project and return Privacy Act findings. |
| `attestlens_scan_url` | Scan a public URL and return live-site findings. |
| `attestlens_audit` | Run a full APP/NDB audit and return a compliance report. |
| `attestlens_map` | Map supplied findings to APP/NDB obligations. |
| `attestlens_opinion` | Generate a deterministic compliance opinion. |
| `attestlens_check` | Check one APP principle and return the relevant result. |
| `attestlens_compliance_check` | Run the SMB compliance-check workflow. |
| `attestlens_reform` | Assess Privacy Act reform exposure and remediation needs. |

## CLI Reference

| Command or mode | Example | Purpose |
| --- | --- | --- |
| `scan` | `npx @attestlens/cli scan ./my-project` | Run a fast project or URL assessment. |
| `audit` | `npx @attestlens/cli audit ./my-project -n "My Business"` | Produce a full APP/NDB compliance report. |
| `opinion` | `npx @attestlens/cli audit ./my-project --opinion --format agent` | Include the deterministic compliance opinion in the audit output. |
| `compliance-check` | `npx @attestlens/cli compliance-check ./my-project` | Run the SMB-focused plain-English compliance workflow. |
| `reform` | `npx @attestlens/cli audit ./my-project --reform` | Include Privacy Act reform impact and remediation guidance. |
| `attest` | `npx @attestlens/cli attest ./my-project` | Start or resume a questionnaire-backed attestation session. |

Common report formats:

```bash
npx @attestlens/cli audit ./my-project --format html,json,markdown,pdf
npx @attestlens/cli audit ./my-project --format agent --opinion
```

Useful assessment flags:

```bash
npx @attestlens/cli scan ./my-project --external-enrichment
npx @attestlens/cli scan ./my-project --scanner-timeout 60000
npx @attestlens/cli audit ./my-project --strict
```

## Architecture

Clearway separates collection, mapping, opinion, and reporting:

1. Scanner adapters collect project, URL, MCP, supply-chain, behavioral, and infrastructure evidence.
2. The mapping engine links findings to Australian Privacy Principles and NDB obligations.
3. The opinion engine produces deterministic compliance opinions from structured findings and questionnaire evidence.
4. Report writers produce human-readable, JSON, PDF, and agent-native formats.
5. The MCP server exposes the same assessment model through structured Zod schemas.

Compliance opinions do not rely on LLM calls. AI agents can run Clearway and consume the structured output, but the compliance verdict is produced by deterministic code.

## Contributing

Read the project docs before changing scanner, report, or MCP behavior:

- [Status](docs/STATUS.md)
- [Roadmap](docs/ROADMAP.md)
- [Validation runbook](docs/validation/ATTESTATION-RUNBOOK.md)

## License

MIT
