# Clearway YC Demo Script

**Demo goal:** show Clearway as a deterministic privacy deploy gate for AI-generated software.

Clearway is not legal advice and does not claim global compliance. It checks technical evidence against coverage-bounded jurisdiction packs and returns deploy-gate signals that CI and MCP-compatible agents can act on.

---

## 60-second flow

### 0-10 seconds: Agent introduces risky code

Open a pull request where an AI coding agent logs a signup request body:

```js
export async function POST(request) {
  const body = await request.json();
  console.log('new signup request', { email: body.email, plan: body.plan });
  return Response.json({ ok: true });
}
```

Say:

> An AI coding agent just added a normal-looking debug line, but it sends personal data into application logs. This is exactly the kind of fast software change that can bypass manual privacy review.

### 10-30 seconds: Clearway flags it

Run the gate:

```bash
npx -y --package @attestlens/cli@beta attestlens audit demo/agent-pr-privacy-risk/pii-log-fail \
  --jurisdiction au-privacy-act \
  --format sarif \
  --sarif-output clearway-pii-log.sarif \
  --no-guardvibe \
  --no-mcp-scan \
  --no-supply-chain \
  --no-behavioral \
  --fail-on-severity warning
```

Expected result:

- Clearway emits SARIF for GitHub code scanning.
- The command exits non-zero because this demo policy treats Clearway `WARN` and above as CI-failing for the current internal-validated pack.
- The finding maps to privacy/security obligations such as protecting personal information in logs.

Say:

> Clearway is not asking a model whether this looks bad. The runtime is deterministic. The rule fires, maps to a jurisdiction pack, emits SARIF, and the deploy policy fails the PR.

### 30-50 seconds: Agent fixes it

Apply the remediated version that logs only non-identifying operational fields:

```js
export async function POST(request) {
  const body = await request.json();
  const contactProvided = typeof body.email === 'string' && body.email.length > 0;
  const plan = typeof body.plan === 'string' ? body.plan : 'unknown';
  console.info('new signup request', { contactProvided, plan });
  return Response.json({ ok: true });
}
```

Run:

```bash
npx -y --package @attestlens/cli@beta attestlens audit demo/agent-pr-privacy-risk/pii-log-pass \
  --jurisdiction au-privacy-act \
  --format sarif \
  --sarif-output clearway-pii-log-pass.sarif \
  --no-guardvibe \
  --no-mcp-scan \
  --no-supply-chain \
  --no-behavioral \
  --fail-on-severity warning
```

Expected result:

- The command exits 0.
- SARIF is still generated.
- The PR can proceed because no in-scope deploy-gate issue remains.

### 50-60 seconds: Close the story

Say:

> The product is a privacy deploy gate for AI-generated software. Start in advisory mode, measure false positives, then block only deterministic or high-confidence checks. The long-term product is a policy runtime every agent calls before touching customer data or production.

Optional strict local proof:

```bash
npx -y --package @attestlens/cli@beta attestlens audit demo/agent-pr-privacy-risk/fail \
  --jurisdiction au-privacy-act \
  --format sarif \
  --sarif-output clearway-strict.sarif \
  --no-guardvibe \
  --no-mcp-scan \
  --no-supply-chain \
  --no-behavioral \
  --allow-internal-validation-blocking \
  --fail-on-severity error
```

This local/demo override proves strict blocking mechanics without changing the embedded pack validation status.

---

## GitHub Actions demo

The repository includes:

- `.github/workflows/ci.yml` for standard TypeScript validation.
- `.github/workflows/clearway-gate.yml` for repo SARIF visibility plus deterministic PII logging and strict local blocking fixtures.
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
  --fail-on-severity warning
```
