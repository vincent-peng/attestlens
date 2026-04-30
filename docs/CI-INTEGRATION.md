# CI/CD Integration Guide

AttestLens can run multi-jurisdiction compliance checks in your CI/CD pipeline before they ship.

## Quick Start

Add this to `.github/workflows/compliance.yml`:

```yaml
name: Privacy Compliance
on: [pull_request]
jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npx @attestlens/cli audit . --opinion --format agent
```

The `--format agent` flag outputs machine-readable JSON. Exit code 1 means NON_COMPLIANT.

## Opinion Gate

Fail the build on non-compliant opinions:

```yaml
- run: npx @attestlens/cli audit . --opinion --format agent
  # Exit code 1 = NON_COMPLIANT, 0 = COMPLIANT/PARTIALLY_COMPLIANT
```

## Multi-Jurisdiction Gates

Run the same audit against a specific jurisdiction pack:

```yaml
- run: npx @attestlens/cli audit . --jurisdiction eu-gdpr --opinion --format agent
- run: npx @attestlens/cli audit . --jurisdiction us-ccpa --opinion --format agent
```

## Single-Principle Gates

Use the MCP tool `attestlens_check` for targeted checks via the MCP server:

```yaml
- run: |
    npx attestlens-mcp &
    sleep 2
    # Use MCP client to call attestlens_check with principle: APP_11
```

## Advanced: Full Audit with Reports

```yaml
name: Nightly Compliance Audit
on:
  schedule:
    - cron: "0 2 * * *"
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npx @attestlens/cli audit . --opinion --format html,json,markdown
      - uses: actions/upload-artifact@v4
        with:
          name: compliance-reports
          path: attestlens-reports/
```

## MCP Server in CI

Run the MCP server for agent-driven checks:

```yaml
- run: npx attestlens-mcp --help
  # Start server: npx attestlens-mcp
  # Tools: attestlens_scan, attestlens_scan_url, attestlens_audit, attestlens_map,
  #        attestlens_opinion, attestlens_check, attestlens_compliance_check, attestlens_reform
```

## CLI Flags Reference

| Flag | Description | CI Use |
|------|-------------|--------|
| `--format agent` | Machine-readable JSON | Pipe to other tools |
| `--format json` | Full JSON report | Artifact upload |
| `--opinion` | Include compliance opinion | Gate on verdict |
| `--jurisdiction` | Select jurisdiction pack | AU, US, or EU gates |
| `--strict` | Treat UNKNOWN as FAIL | Strict mode |
| `--no-mcp-scan` | Skip MCP scanning | Faster CI |
| `--no-supply-chain` | Skip supply chain | Faster CI |
| `--no-behavioral` | Skip behavioral | Faster CI |
| `--no-iac` | Skip IaC scanning | Faster CI |
