# Clearway by AttestLens

**The privacy deploy gate for AI-generated software.**

Clearway runs before AI coding agents merge code or release changes. It scans code, live URLs, dependencies, and infrastructure signals; maps evidence to privacy-law obligations; and returns deterministic deploy verdicts that CI systems and MCP-compatible agents can act on.

Clearway is **not** a generic GRC platform, not a legal-advice engine, and not a chatbot over compliance docs. It is a runtime gate for agent-created software changes.

## Why this exists

AI agents are now writing code, changing dependencies, creating routes, wiring analytics, and modifying data flows faster than privacy and security teams can manually review every change.

That creates a new failure mode:

> An agent can accidentally ship a privacy violation before a human realizes what changed.

Clearway turns privacy review into a deterministic pre-merge check.

```bash
npx -y --package @attestlens/cli@beta attestlens audit . \
  --jurisdiction eu-gdpr \
  --opinion \
  --format agent
```

Example verdict:

```json
{
  "verdict": "NEEDS_REVIEW",
  "jurisdiction": "eu-gdpr",
  "principle": "GDPR_Art6",
  "reason": "New processing path touches personal data without detected lawful-basis evidence.",
  "confidence": "MODERATE",
  "blocking": false,
  "nextAction": "Attach lawful-basis evidence or mark this route as out of scope."
}
```

## Product thesis

Clearway has two layers:

1. **Runtime gate** — deterministic CLI, CI, SARIF, and MCP tools for agents and developers.
2. **Jurisdiction-pack system** — versioned privacy-law rule packs with explicit coverage boundaries, citations, provenance, validation status, and tests.

The runtime stays deterministic. AI may help draft rules, but only human-validated rules can become blocking.

## Current jurisdiction packs

| Jurisdiction | Role | Status | Pitch language |
| --- | --- | --- | --- |
| `au-privacy-act` | Deep seed pack and proof of legal mapping | Live | Strongest current pack |
| `us-ccpa` | US commercial wedge | Early live pack | Coverage-bounded |
| `eu-gdpr` | International credibility pack | Early live pack | Coverage-bounded GDPR subset |
| `sg-pdpa` | Portability proof | Beta/stub | Do not lead with this |

Clearway is **multi-jurisdiction**, not “global compliance.” Every pack must state what it covers and what it does not cover.

## Install and run

Use `--package` to ensure the correct npm binary is invoked.

```bash
npx -y --package @attestlens/cli@beta attestlens scan ./my-project
npx -y --package @attestlens/cli@beta attestlens audit ./my-project --opinion
```

Run against a specific jurisdiction:

```bash
npx -y --package @attestlens/cli@beta attestlens audit ./my-project \
  --jurisdiction au-privacy-act \
  --opinion \
  --format html,json,sarif

npx -y --package @attestlens/cli@beta attestlens audit ./my-project \
  --jurisdiction us-ccpa \
  --opinion \
  --format agent

npx -y --package @attestlens/cli@beta attestlens audit ./my-project \
  --jurisdiction eu-gdpr \
  --opinion \
  --format agent
```

## CI deploy gate

Clearway separates SARIF visibility from CI failure policy. Start in advisory mode, then choose whether WARN or only BLOCK deploy decisions should fail the build.

Advisory mode:

```bash
npx -y --package @attestlens/cli@beta attestlens audit . \
  --jurisdiction eu-gdpr \
  --opinion \
  --format sarif \
  --sarif-output clearway.sarif \
  --no-fail
```

Fail on WARN or BLOCK:

```bash
npx -y --package @attestlens/cli@beta attestlens audit . \
  --jurisdiction eu-gdpr \
  --opinion \
  --format sarif \
  --sarif-output clearway.sarif \
  --fail-on-severity warning
```

Fail only on BLOCK:

```bash
npx -y --package @attestlens/cli@beta attestlens audit . \
  --jurisdiction eu-gdpr \
  --opinion \
  --format sarif \
  --sarif-output clearway.sarif \
  --fail-on-severity error
```

Current `internal_validated` packs produce `WARN` for blocking candidates by default. Use `--allow-internal-validation-blocking` only as a local/demo/self-hosted override when you explicitly trust the embedded pack enough to turn those candidates into `BLOCK`; it is not the recommended default posture for third-party CI rollout.

Recommended rollout:

1. Run in advisory mode with `--no-fail`.
2. Tune suppressions and rule confidence.
3. Fail on `WARN`/`BLOCK` with `--fail-on-severity warning`.
4. Move to `--fail-on-severity error` only when the selected packs and policy allow true `BLOCK` decisions.

## MCP integration

Add Clearway to an MCP-compatible client:

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

MCP tools:

| Tool | Purpose |
| --- | --- |
| `attestlens_scan` | Scan a local project |
| `attestlens_scan_url` | Scan a public URL |
| `attestlens_audit` | Full audit and report |
| `attestlens_map` | Map findings to regulation controls |
| `attestlens_opinion` | Generate deterministic compliance opinion |
| `attestlens_check` | Check one principle/control |
| `attestlens_compliance_check` | AU SMB compliance workflow |
| `attestlens_reform` | AU reform impact workflow |

## What Clearway is not

Clearway is not legal advice. It is not a substitute for counsel, audit, or privacy-program governance. It is a deterministic technical gate that helps teams detect and block privacy-risky software changes before they ship.

## What makes it different

- **Agent-native:** CLI + MCP + compact agent JSON.
- **Deterministic:** no LLM calls at scan runtime.
- **Pack-based:** jurisdictions are versioned rule packs, not vague prompts.
- **Evidence-backed:** findings map to specific controls, citations, and remediation.
- **Deploy-gate first:** built to block or warn in CI, not just generate PDFs.

## YC focus

For YC, the product should be described as:

> We make AI coding agents comply with privacy law before they merge code.

The long-term company is the policy runtime for agents: any agent action that touches customer data should pass through a deterministic, evidence-backed policy gate before it reaches production.

## License

MIT
