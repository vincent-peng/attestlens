# CI/CD Integration Guide

Clearway can run privacy deploy checks in CI before AI-generated or human-written changes merge.

Clearway is a technical deploy gate, not legal advice. Start in advisory mode, measure false positives, then enable blocking only for high-confidence deterministic findings.

---

## In this repository

This repo includes two GitHub Actions workflows:

- `.github/workflows/ci.yml` runs TypeScript validation, tests, and build.
- `.github/workflows/clearway-gate.yml` builds the local package, generates SARIF for the repo in advisory mode, filters intentional demo-fixture findings from the uploaded advisory SARIF, and verifies a deterministic failing/passing demo fixture.

The internal Clearway workflow does not make `main` permanently fail. It runs the repository scan in advisory mode, then proves blocking behavior against `demo/agent-pr-privacy-risk/fail` and proves the remediated version passes against `demo/agent-pr-privacy-risk/pass`.

Run the same fixture locally:

```bash
npx -y --package @attestlens/cli@beta attestlens audit demo/agent-pr-privacy-risk/fail \
  --jurisdiction au-privacy-act \
  --format sarif \
  --sarif-output clearway.sarif \
  --no-guardvibe \
  --no-mcp-scan \
  --no-supply-chain \
  --no-behavioral \
  --fail-on-severity error

npx -y --package @attestlens/cli@beta attestlens audit demo/agent-pr-privacy-risk/pass \
  --jurisdiction au-privacy-act \
  --format sarif \
  --sarif-output clearway-pass.sarif \
  --no-guardvibe \
  --no-mcp-scan \
  --no-supply-chain \
  --no-behavioral \
  --fail-on-severity error
```

The first command should exit non-zero. The second should pass. Both generate SARIF.

---

## Copy-paste advisory workflow

Add this to `.github/workflows/clearway-advisory.yml`:

```yaml
name: Clearway Privacy Advisory

on:
  pull_request:

permissions:
  actions: read
  contents: read
  security-events: write

jobs:
  clearway:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: Run Clearway in advisory mode
        run: |
          npx -y --package @attestlens/cli@beta attestlens audit . \
            --jurisdiction eu-gdpr \
            --opinion \
            --format sarif \
            --sarif-output clearway.sarif \
            --no-fail

      - name: Upload SARIF
        if: ${{ always() && hashFiles('clearway.sarif') != '' }}
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: clearway.sarif
          category: clearway-privacy
```

Use advisory mode first. This creates visibility without blocking PRs.

---

## Blocking workflow

After tuning, enable blocking for high-confidence findings:

```yaml
name: Clearway Privacy Gate

on:
  pull_request:

permissions:
  actions: read
  contents: read
  security-events: write

jobs:
  clearway:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: Run Clearway gate
        run: |
          npx -y --package @attestlens/cli@beta attestlens audit . \
            --jurisdiction au-privacy-act \
            --opinion \
            --format sarif \
            --sarif-output clearway.sarif \
            --fail-on-severity error

      - name: Upload SARIF
        if: ${{ always() && hashFiles('clearway.sarif') != '' }}
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: clearway.sarif
          category: clearway-privacy
```

The build fails through the CLI exit code, not because SARIF itself blocks the PR. SARIF is for annotations and visibility.

For a complete copy-paste workflow, see `examples/github-action/clearway.yml`.

---

## Agent-readable output

For MCP clients, coding agents, or CI log parsing:

```bash
npx -y --package @attestlens/cli@beta attestlens audit . \
  --jurisdiction us-ccpa \
  --opinion \
  --format agent
```

The desired future shape is an operational deploy decision:

- `BLOCK`
- `WARN`
- `NEEDS_REVIEW`
- `PASS`
- `OUT_OF_SCOPE`

Until the deploy-verdict schema lands, treat existing compliance/opinion output as decision-support rather than a legal conclusion.

---

## Multi-jurisdiction matrix

```yaml
strategy:
  matrix:
    jurisdiction: [au-privacy-act, us-ccpa, eu-gdpr]

steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-node@v4
    with:
      node-version: 20
  - run: |
      npx -y --package @attestlens/cli@beta attestlens audit . \
        --jurisdiction ${{ matrix.jurisdiction }} \
        --opinion \
        --format agent
```

Do not call this “global compliance.” Each jurisdiction pack is coverage-bounded.

---

## MCP server in local agent workflows

Use this command in MCP client config:

```bash
npx -y --package @attestlens/cli@beta attestlens-mcp
```

Typical MCP config:

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

---

## Rollout plan

1. Local scan on one repo.
2. Advisory CI mode.
3. Tune suppressions and false positives.
4. Enable blocking only for high-confidence deterministic findings.
5. Expand jurisdictions and repos after validation.

---

## CLI flags reference

| Flag | Description | CI use |
| --- | --- | --- |
| `--format agent` | Compact machine-readable output | Agent workflows |
| `--format sarif` | SARIF output | GitHub code scanning |
| `--sarif-output <path>` | SARIF destination | Upload artifact/SARIF |
| `--opinion` | Include deterministic opinion output | Decision-support |
| `--jurisdiction` | Select jurisdiction pack | AU, CCPA, GDPR, SG |
| `--fail-on-severity` | Non-zero exit at threshold | Blocking gate |
| `--no-fail` | Always exit 0 | Advisory mode |
| `--strict` | Treat unknowns as failing | Conservative mode |
| `--no-mcp-scan` | Skip MCP scanning | Faster CI |
| `--no-supply-chain` | Skip supply chain | Faster CI |
| `--no-behavioral` | Skip behavioral analysis | Faster CI |
| `--no-iac` | Skip IaC scanning | Faster CI |
