# Pricing — Protected Repo/Pipeline Model

**Status:** Use this as the current pricing source of truth.  
**Decision:** Do not price as a low-cost indie tool. Price as an infrastructure gate.

---

## Pricing principle

Charge by protected software surface, not by human seat and not by scan count.

Why:

- AI agents do not map cleanly to human seats.
- Frequent scans are the desired behavior.
- The value is protecting repos/pipelines from risky changes.
- Customers should not hesitate before running another preflight check.

---

## Recommended tiers

### Free — $0

For adoption and local experimentation.

Includes:

- Local CLI scan.
- MCP server.
- One protected private repo.
- Basic AU/CCPA/GDPR pack access.
- JSON/HTML/agent output.
- No hosted evidence retention.
- Community support.

### Pro — $199/month per 5 protected repos or pipelines

For startups and small teams.

Includes:

- Unlimited scans per protected repo/pipeline.
- CI deploy gating.
- SARIF output.
- Agent-native output.
- Opinion/deploy decision output.
- Evidence retention in local artifacts.
- Suppression config.
- Basic support.
- AU + CCPA + GDPR coverage-bounded packs.

### Team — $499/month per 15 protected repos or pipelines

For growing SaaS teams.

Includes Pro plus:

- Team policy config.
- Multi-jurisdiction matrix scans.
- PR-diff mode.
- Slack/email webhook alerts.
- Evidence trend exports.
- Priority support.

### Enterprise — $15k-$50k+/year

For regulated or larger companies.

Includes Team plus:

- Self-hosted or air-gapped deployment.
- SSO/SAML.
- Custom/private jurisdiction packs.
- Private rule validation workflow.
- Legal/privacy partner review workflow.
- Governance integrations such as Vanta/Drata/OneTrust/Jira/Slack.
- Dedicated support and SLA.

---

## Design partner pricing

Do not run unlimited free pilots.

Suggested options:

1. **Paid pilot:** $500-$2,000 for a two- to four-week founder-led pilot.
2. **Free pilot with conversion path:** free two-week shadow scan, then $199/month if they keep it in CI.
3. **Enterprise discovery pilot:** $5k for custom rules or private pack validation.

Every pilot should have a conversion conversation upfront.

---

## What not to do

Do not price per scan.

Do not price per agent call.

Do not start at $29/month for the primary Pro tier. That signals “side-project devtool,” not “critical policy gate.” A lower introductory price is fine for early design partners, but the list price should reflect infrastructure value.

---

## Packaging by customer stage

### Solo developer / open source

Free local CLI + MCP.

Goal: adoption and public examples.

### Seed-stage SaaS

$199/month.

Goal: get into CI before they have a full security/privacy team.

### Series A/B SaaS

$499/month or $5k/year.

Goal: multiple repos, agent workflows, international packs.

### Enterprise

$15k-$50k/year.

Goal: self-hosting, custom packs, validation workflows, governance integrations.

---

## Pricing test in pilots

Ask directly:

- Would you pay $199/month to keep this in CI?
- Would you pay $499/month if it covered all repos with evidence retention?
- Would you pay for custom rules or private pack validation?
- Would this budget come from engineering, security, privacy, or compliance?

The answer matters more than the list price.
