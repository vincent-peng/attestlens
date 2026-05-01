# Phase 10.5: GitHub Action + MCP Distribution — Implementation Spec

**Date:** 2026-05-01
**Status:** Ready for implementation
**Timebox:** 1-2 days
**Research base:** `docs/RESEARCH-PHASE-10.5-11.md`

---

## Overview

Add SARIF output, CI exit-threshold controls, GitHub Action wrapper, npm polish, and MCP Registry metadata. This is plumbing — get it done fast so we can focus on Phase 11 (the moat).

---

## Step 1: SARIF Exporter (`--format sarif`)

### What to build

Add `--format sarif` flag to the CLI's `scan` and `audit` commands. When specified, output a valid SARIF v2.1.0 JSON file instead of the default report format.

### File changes

- `src/cli/index.ts` — Add `--format` option to scan/audit commands (values: `json`, `sarif`; default: current behavior)
- `src/formatters/sarif.ts` — New file: SARIF formatter

### SARIF output spec

```typescript
interface SarifOutput {
  $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json";
  version: "2.1.0";
  runs: SarifRun[];
}

interface SarifRun {
  tool: {
    driver: {
      name: "Clearway";
      version: string; // from package.json
      informationUri: "https://clearway.ai";
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
}

interface SarifRule {
  id: string;                    // e.g., "AU.APP.11.1.policy-accessible"
  name: string;                  // e.g., "PolicyAccessible"
  shortDescription: { text: string };
  fullDescription: { text: string };
  helpUri: string;                // e.g., "https://clearway.ai/rules/AU.APP.11.1.policy-accessible"
  properties: {
    tags: string[];               // e.g., ["privacy", "au-privacy-act", "app-11"]
    precision: "very-high" | "high" | "medium" | "low";
    "problem.severity": "error" | "warning" | "recommendation";
  };
}
```

### Rule ID format

Use jurisdiction-qualified IDs: `AU.APP.11.1.policy-accessible`, `US.CCPA.1798.100.disclosure`, `EU.GDPR.ART.13.privacy-notice`

This is a change from the current internal IDs (e.g., `APP-11-1`). Map internal IDs to SARIF IDs using the PrincipleRegistry.

### Severity mapping

| Clearway Finding | SARIF `level` | `properties.problem.severity` | `properties.precision` |
|---|---|---|---|
| High confidence, blocking | `error` | `error` | `high` or `very-high` |
| Medium confidence, advisory | `warning` | `warning` | `medium` |
| Low confidence, informational | `note` | `recommendation` | `low` |

**Do NOT set `properties.security-severity`** — these are compliance findings, not security vulnerabilities.

### Partial fingerprints

Generate `primaryLocationLineHash` from:
- Normalized rule ID
- Normalized file path (relative to repo root)
- Line number

Use a stable hash function (SHA-256 truncated to 16 hex chars is fine).

### File path handling

- All `artifactLocation.uri` values must be relative paths (not absolute)
- Resolve symlinks before reporting
- Use the scan target directory as the base for relativization

### Exit behavior

When `--format sarif` is used:
- Write SARIF to stdout OR to a file (add `--sarif-output <path>` flag)
- Exit code is determined by `--fail-on-severity` (Step 2), not by whether findings exist
- If SARIF write fails, exit with code 2

### Tests

- Unit test: `sarif.test.ts` — verify SARIF output structure, rule mapping, severity mapping, fingerprint generation, file path relativization
- Integration test: run `attestlens scan --format sarif --jurisdiction au-privacy-astest fixture` and validate output against SARIF schema
- Test with zero findings (empty results array is valid)
- Test with findings that have no file location (use a synthetic location)

---

## Step 2: CLI Exit-Threshold Controls

### What to build

Add `--fail-on-severity` flag to `scan` and `audit` commands. This controls the **process exit code**, separate from SARIF output severity.

### Behavior

```
--fail-on-severity error     → exit 1 only if any "error" findings exist (default)
--fail-on-severity warning   → exit 1 if any "warning" or "error" findings exist
--fail-on-severity note      → exit 1 if any findings exist at all
--no-fail                    → always exit 0 (useful for "always upload SARIF" workflow)
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | No findings above threshold (or `--no-fail`) |
| 1 | Findings above threshold exist |
| 2 | Tool error (invalid args, scan failure, etc.) |

### File changes

- `src/cli/index.ts` — Add `--fail-on-severity` option (default: `error`) and `--no-fail` flag
- Scan/audit command handlers — Check findings against threshold before exit

### Tests

- Test that exit code is 0 when no findings above threshold
- Test that exit code is 1 when findings above threshold exist
- Test that `--no-fail` always exits 0
- Test that invalid args exit with code 2

---

## Step 3: GitHub Composite Action

### What to build

Create a new repo `github.com/vincent-peng/clearway-action` (or `attestlens/action` — decide naming later). This is a thin wrapper around the CLI.

### action.yml

```yaml
name: 'Clearway Privacy Compliance Scanner'
description: 'Scan for privacy compliance violations (AU Privacy Act, US CCPA, EU GDPR)'
branding:
  icon: 'shield'
  color: 'green'

inputs:
  jurisdiction:
    description: 'Jurisdiction pack(s) to scan (au-privacy-act, us-ccpa, eu-gdpr, all)'
    required: false
    default: 'all'
  fail-on-severity:
    description: 'Minimum severity to fail the action (error, warning, note)'
    required: false
    default: 'error'
  sarif-output:
    description: 'Path to write SARIF output file'
    required: false
    default: '${{ runner.temp }}/clearway-results.sarif'
  no-fail:
    description: 'Always exit 0 (for advisory-only workflows)'
    required: false
    default: 'false'
  config-path:
    description: 'Path to clearway config file'
    required: false
    default: ''
  version:
    description: 'Clearway CLI version to install'
    required: false
    default: 'latest'

outputs:
  sarif-file:
    description: 'Path to the generated SARIF file'
    value: ${{ steps.scan.outputs.sarif-file }}
  violation-count:
    description: 'Total number of violations found'
    value: ${{ steps.scan.outputs.violation-count }}
  error-count:
    description: 'Number of error-level violations'
    value: ${{ steps.scan.outputs.error-count }}
  warning-count:
    description: 'Number of warning-level violations'
    value: ${{ steps.scan.outputs.warning-count }}

runs:
  using: 'composite'
  steps:
    - name: Install Clearway
      shell: bash
      run: |
        npm install -g @attestlens/cli@${{ inputs.version }}
    - name: Run Clearway Scan
      id: scan
      shell: bash
      run: |
        ARGS="--format sarif --sarif-output ${{ inputs.sarif-output }} --jurisdiction ${{ inputs.jurisdiction }} --fail-on-severity ${{ inputs.fail-on-severity }}"
        if [ "${{ inputs.no-fail }}" = "true" ]; then
          ARGS="$ARGS --no-fail"
        fi
        if [ -n "${{ inputs.config-path }}" ]; then
          ARGS="$ARGS --config ${{ inputs.config-path }}"
        fi
        attestlens scan $ARGS .
        echo "sarif-file=${{ inputs.sarif-output }}" >> "$GITHUB_OUTPUT"
        # Parse counts from JSON output (add --json-output flag for counts)
    - name: Upload SARIF
      if: always()
      uses: github/codeql-action/upload-sarif@v4
      with:
        sarif_file: ${{ inputs.sarif-output }}
        category: clearway-${{ inputs.jurisdiction }}
```

**⚠️ Note:** This is a starting point. The actual implementation should:
1. Handle the `if: always()` upload pattern correctly (let the caller decide whether to upload)
2. NOT include the upload step in the composite action — let the caller's workflow handle upload
3. Parse and expose violation counts as outputs
4. Handle `npx` as an alternative to global install

### Recommended caller pattern

The action should NOT include `upload-sarif`. Instead, show this in the README:

```yaml
- uses: actions/checkout@v4
- uses: clearway/clearway-action@v1
  id: clearway
  with:
    jurisdiction: 'all'
    fail-on-severity: 'error'
- uses: github/codeql-action/upload-sarif@v4
  if: always()
  with:
    sarif_file: ${{ steps.clearway.outputs.sarif-file }}
    category: clearway-privacy
```

### Repo structure

```
clearway-action/
├── action.yml
├── README.md
├── examples/
│   ├── strict.yml          # Blocks PR on error findings
│   ├── advisory.yml         # Always uploads, never blocks
│   └── matrix.yml           # Per-jurisdiction matrix
└── LICENSE
```

**This is a separate repo from the main attestlens package. Create it when npm package is published and versioned.**

---

## Step 4: npm Package Polish

### What to change

Add `mcpName` to `package.json`:

```json
{
  "name": "@attestlens/cli",
  "version": "0.4.0",
  "mcpName": "io.github.attestlens/clearway",
  "description": "Clearway — Privacy Compliance Deploy Gate for AI Agents",
  "bin": {
    "attestlens": "./dist/cli.js",
    "attestlens-mcp": "./dist/mcp.js"
  },
  "keywords": ["mcp", "mcp-server", "model-context-protocol", "privacy", "compliance", "sarif", "clearway", "attestlens", "deploy-gate"]
}
```

Verify `npm pack --dry-run` still works and produces a clean package.

### File changes

- `package.json` — Add `mcpName`, update description, add `sarif` and `deploy-gate` keywords
- Verify all existing tests still pass

---

## Step 5: MCP Registry Metadata (`server.json`)

### What to build

Create `server.json` for the official MCP Registry:

```json
{
  "name": "io.github.attestlens/clearway",
  "version": "0.4.0",
  "description": "Clearway MCP server — Privacy compliance scanning and deploy gating for AI agents",
  "transport": "stdio",
  "tools": [
    {
      "name": "attestlens_scan",
      "description": "Scan a local project directory for privacy compliance violations"
    },
    {
      "name": "attestlens_scan_url",
      "description": "Scan a URL for privacy compliance violations"
    },
    {
      "name": "attestlens_audit",
      "description": "Audit a project's privacy compliance posture"
    },
    {
      "name": "attestlens_opinion",
      "description": "Generate a compliance opinion for a project"
    },
    {
      "name": "attestlens_check",
      "description": "Check a single regulation principle"
    },
    {
      "name": "attestlens_compliance_check",
      "description": "Run SMB compliance questionnaire check"
    },
    {
      "name": "attestlens_map",
      "description": "Map findings to regulation principles"
    },
    {
      "name": "attestlens_reform",
      "description": "Generate reform recommendations"
    }
  ],
  "resources": [],
  "repository": "https://github.com/vincent-peng/attestlens",
  "npmPackage": "@attestlens/cli"
}
```

### Where to put it

`server.json` at the repo root (alongside package.json). This is the official MCP Registry metadata format.

---

## Step 6: CLI Installer (`attestlens install`)

### What to build

Add `install` and `uninstall` subcommands to the CLI that:
1. Detect installed MCP clients (Claude Desktop, Cline, Continue, Cursor, VS Code)
2. Add/remove the Clearway MCP server config to the client's settings
3. Verify the connection works

### Detection logic

- **Claude Desktop:** `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS), `%APPDATA%\Claude\claude_desktop_config.json` (Windows)
- **Cline:** VS Code settings.json with `cline.mcpServers` key
- **Continue:** `~/.continue/config.json` with `mcpServers` key
- **Cursor:** `~/.cursor/mcp.json`

### Config to add

```json
{
  "mcpServers": {
    "clearway": {
      "command": "npx",
      "args": ["-y", "@attestlens/cli", "mcp"],
      "transport": "stdio"
    }
  }
}
```

### Implementation

- `src/cli/install.ts` — New file: detect clients, add/remove config
- `src/cli/index.ts` — Register `install` and `uninstall` subcommands
- Back up existing config before modifying
- Handle missing/empty config gracefully
- Support `--client <name>` flag for specific client
- Support `--dry-run` flag to show what would change

### Tests

- Unit test: mock filesystem, verify config merge logic
- Test: backup creation before modification
- Test: idempotent (running install twice produces same config)
- Test: uninstall restores original config

---

## Step 7: CI Integration Docs Update

### What to update

Update `docs/CI-INTEGRATION.md` with:
1. GitHub Action usage examples (strict, advisory, matrix)
2. SARIF format documentation
3. Exit threshold documentation
4. MCP server CI usage patterns
5. Security model for CI (no secrets needed, offline scan, minimal permissions)

---

## Implementation Order

1. **Step 1 (SARIF exporter)** — This is the foundation everything else depends on
2. **Step 2 (Exit threshold)** — Small change, but critical for CI behavior
3. **Step 4 (npm polish)** — Quick, do while tests run
4. **Step 5 (server.json)** — Quick, pure metadata
5. **Step 6 (CLI installer)** — Medium complexity
6. **Step 3 (GitHub Action)** — Depends on Steps 1-2 being done; create separate repo
7. **Step 7 (Docs)** — Last, after everything works

Steps 3 (GitHub Action) requires a separate repo and published npm package. Create the action repo only after Steps 1-2 are merged and the npm package is published.

---

## Testing Requirements

- All existing 523 tests must continue to pass
- New SARIF formatter tests (unit + integration)
- New exit-threshold tests
- New CLI installer tests (mocked filesystem)
- `npm pack --dry-run` must pass
- `tsc --noEmit` must be clean

---

## Security Checklist

- [ ] SARIF output does not include absolute file paths (relative only)
- [ ] `--fail-on-severity` and `--no-fail` cannot be bypassed by malicious input
- [ ] CLI installer backs up config before modifying
- [ ] No secrets or tokens in SARIF output
- [ ] GitHub Action uses minimal permissions (`security-events: write` only)
- [ ] Action pins npm package version by default