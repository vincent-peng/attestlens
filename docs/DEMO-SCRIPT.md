# Clearway YC Demo Script

**Demo goal:** show Clearway as a deterministic privacy deploy gate for AI-generated software.

Clearway is not legal advice and does not claim global compliance. It checks technical evidence against coverage-bounded jurisdiction packs and returns deploy-gate signals that CI and MCP-compatible agents can act on.

---

## 60-second flow

### 0-10 seconds: Agent introduces risky code

Open a pull request where an AI coding agent adds a production Dockerfile that runs as root:

```dockerfile
FROM node:latest
USER root
```

Say:

> An AI coding agent just changed production runtime configuration. This is exactly the kind of fast software change that can bypass manual privacy and security review.

### 10-30 seconds: Clearway flags it

Run the gate:

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
```

Expected result:

- Clearway emits SARIF for GitHub code scanning.
- The command exits non-zero because a high-confidence deterministic issue crossed the blocking threshold.
- The finding maps to privacy/security obligations such as protecting personal information.

Say:

> Clearway is not asking a model whether this looks bad. The runtime is deterministic. The rule fires, maps to a jurisdiction pack, emits SARIF, and blocks the PR.

### 30-50 seconds: Agent fixes it

Apply the remediated version:

```dockerfile
FROM node:20.12.2-alpine
USER node
HEALTHCHECK CMD node -e "process.exit(0)"
```

Run:

```bash
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

Expected result:

- The command exits 0.
- SARIF is still generated.
- The PR can proceed because no in-scope blocking issue remains.

### 50-60 seconds: Close the story

Say:

> The product is a privacy deploy gate for AI-generated software. Start in advisory mode, measure false positives, then block only high-confidence deterministic checks. The long-term product is a policy runtime every agent calls before touching customer data or production.

---

## GitHub Actions demo

The repository includes:

- `.github/workflows/ci.yml` for standard TypeScript validation.
- `.github/workflows/clearway-gate.yml` for repo SARIF visibility plus a deterministic blocking fixture.
- `examples/github-action/clearway.yml` as the copy-paste workflow for external users.

Use advisory mode first:

```bash
npx -y --package @attestlens/cli@beta attestlens audit . \
  --jurisdiction au-privacy-act \
  --format sarif \
  --sarif-output clearway.sarif \
  --no-fail
```

Enable blocking only after tuning:

```bash
npx -y --package @attestlens/cli@beta attestlens audit . \
  --jurisdiction au-privacy-act \
  --format sarif \
  --sarif-output clearway.sarif \
  --fail-on-severity error
```
