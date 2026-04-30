# Clearway by AttestLens

<p><strong>Logo placeholder: Clearway by AttestLens</strong></p>

[![npm version](https://img.shields.io/npm/v/%40attestlens%2Fcli.svg)](https://www.npmjs.com/package/@attestlens/cli)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](#license)
[![MCP compatible](https://img.shields.io/badge/MCP-compatible-0f766e.svg)](#mcp-integration)

Clearway — Deterministic compliance runtime for AI agents. Multi-jurisdiction privacy compliance for AU Privacy Act, US CCPA/CPRA, and EU GDPR.

## The Problem

AI agents can ship privacy violations faster than humans can review them. Teams need a compliance check that runs before code reaches production, works in CI, and gives agents structured actions instead of loose legal notes.

Clearway scans codebases and URLs, maps findings to supported jurisdiction obligations, and produces deterministic compliance opinions. The same codebase can be assessed against AU Privacy Act, US CCPA/CPRA, or an EU GDPR subset, with different citations, verdicts, and remediation priorities.

Compliance opinions do not use LLM calls. AI agents can run Clearway and consume the structured output, but the compliance verdict is produced by deterministic code.

## Quick Start

```bash
npx @attestlens/cli scan ./my-project
npx @attestlens/cli scan https://example.com
```

AU Privacy Act remains the default for backward compatibility:

```bash
npx @attestlens/cli audit ./my-project --opinion --format agent
```

Run the same project under different jurisdictions:

```bash
npx @attestlens/cli audit ./my-project --jurisdiction au-privacy-act --opinion --format agent
npx @attestlens/cli audit ./my-project --jurisdiction us-ccpa --opinion --format agent
npx @attestlens/cli audit ./my-project --jurisdiction eu-gdpr --opinion --format agent
```

For the multi-jurisdiction demo:

```bash
bash demo/multi-jurisdiction.sh
```

## Features

| User benefit | What Clearway provides |
| --- | --- |
| Multi-jurisdiction privacy checks | Jurisdiction packs for AU Privacy Act, US CCPA/CPRA, and EU GDPR subset, selected with `--jurisdiction`. |
| Instant compliance opinions | Deterministic opinion bands: `NON_COMPLIANT`, `PARTIALLY_COMPLIANT`, or `COMPLIANT`, with evidence tied to jurisdiction obligations. |
| AI agent integration | 8 MCP tools for project scans, URL scans, full audits, regulation mapping, opinions, single-principle checks, SMB compliance checks, and reform assessments. |
| SMB compliance workflow | Plain-English questions and reports for Australian small and medium businesses. |
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
| `attestlens_scan` | Scan a local project and return findings for the selected jurisdiction. |
| `attestlens_scan_url` | Scan a public URL and return live-site findings for the selected jurisdiction. |
| `attestlens_audit` | Run a full audit and return a jurisdiction-specific compliance report. |
| `attestlens_map` | Map supplied findings to supported jurisdiction obligations. |
| `attestlens_opinion` | Generate a deterministic compliance opinion for the selected jurisdiction. |
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

| Command or mode | Example | Purpose |
| --- | --- | --- |
| `scan` | `npx @attestlens/cli scan ./my-project --jurisdiction eu-gdpr` | Run a fast project or URL assessment. |
| `audit` | `npx @attestlens/cli audit ./my-project -n "My Business" --jurisdiction us-ccpa` | Produce a full jurisdiction-specific compliance report. |
| `opinion` | `npx @attestlens/cli audit ./my-project --jurisdiction au-privacy-act --opinion --format agent` | Include the deterministic compliance opinion in the audit output. |
| `compliance-check` | `npx @attestlens/cli compliance-check ./my-project` | Run the AU SMB-focused plain-English compliance workflow. |
| `reform` | `npx @attestlens/cli audit ./my-project --reform` | Include AU Privacy Act reform impact and remediation guidance. |
| `attest` | `npx @attestlens/cli attest ./my-project --jurisdiction eu-gdpr` | Start or resume a questionnaire-backed attestation session. |

Common report formats:

```bash
npx @attestlens/cli audit ./my-project --format html,json,markdown,pdf
npx @attestlens/cli audit ./my-project --format agent --opinion
```

Useful assessment flags:

```bash
npx @attestlens/cli scan ./my-project --jurisdiction us-ccpa
npx @attestlens/cli scan ./my-project --external-enrichment
npx @attestlens/cli scan ./my-project --scanner-timeout 60000
npx @attestlens/cli audit ./my-project --strict
```

Supported jurisdiction values:

```text
au-privacy-act
us-ccpa
eu-gdpr
```

## Architecture

Clearway separates collection, mapping, opinion, and reporting:

1. Scanner adapters collect project, URL, MCP, supply-chain, behavioral, and infrastructure evidence.
2. Jurisdiction packs define supported principles, rule metadata, citations, and jurisdiction-specific scanner checks.
3. The mapping engine links findings to AU APP/NDB, US CCPA/CPRA, or EU GDPR obligations.
4. The opinion engine produces deterministic compliance opinions from structured findings and questionnaire evidence.
5. Report writers produce human-readable, JSON, PDF, and agent-native formats.
6. The MCP server exposes the same assessment model through structured Zod schemas.

Current jurisdiction coverage is multi-jurisdiction, not global. AU, US, and EU packs are live, and claims should stay conservative until jurisdiction packs have external legal validation.

## Contributing

Read the project docs before changing scanner, report, or MCP behavior:

- [Status](docs/STATUS.md)
- [Roadmap](docs/ROADMAP.md)
- [Validation runbook](docs/validation/ATTESTATION-RUNBOOK.md)

## License

MIT
