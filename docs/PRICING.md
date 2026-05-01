# Clearway — Pricing

**Last Updated:** 2026-05-01
**Status:** Internal planning. Not public. Subject to change before launch.
**Source:** GTM Debate consensus (3 agents, 3 rounds, unanimous)

---

## Pricing Philosophy

1. **Price by protected software surface** (repos/pipelines), not per-scan or per-seat
2. **Unlimited scans** within a subscription — frequent agent preflights should feel free
3. **Jurisdiction packs included** in paid plans — don't gate the core value
4. **MCP is the free adoption wedge** — don't meter agent calls
5. **CI enforcement + evidence retention is the monetized layer**

---

## Tiers

### Free — $0/mo

- Local CLI scanning (code + URL)
- MCP server (all 8 tools, local)
- 1 private repo
- Core jurisdiction packs (AU, US, EU)
- Basic HTML/JSON reports
- No retained evidence
- Community support

### Pro — $99-199/mo per 5 protected repos/pipelines

- Everything in Free
- **Unlimited scans** per protected repo
- CI deploy gating (GitHub Action, GitLab CI)
- Opinion-grade verdicts with regulatory citations
- Reform module + remediation suggestions
- Agent-native report format
- SMB compliance-check workflow
- Full evidence retention (HTML, MD, JSON, PDF)
- Severity-based blocking (configurable thresholds)
- Slack/email alerts for new findings
- Standard support

### Enterprise — $15-50K+/yr

- Everything in Pro
- **Unlimited protected repos/pipelines**
- SSO / SAML
- Self-hosted option (air-gapped)
- Custom jurisdiction packs (private/sector-specific)
- Custom rule authoring pipeline
- Team + org workflows
- OneTrust / Jira / Slack integrations
- Dedicated customer success manager
- Custom compliance reporting
- Named support + SLA

---

## Feature Comparison

| Feature | Free | Pro | Enterprise |
|---|---|---|---|
| Local CLI scan | ✅ | ✅ | ✅ |
| URL scan | ✅ | ✅ | ✅ |
| MCP server (8 tools) | ✅ | ✅ | ✅ |
| Jurisdiction packs | AU, US, EU | AU, US, EU | All + custom |
| Private repos | 1 | 5 per unit | Unlimited |
| Scans per repo | Unlimited | Unlimited | Unlimited |
| CI deploy gating | ❌ | ✅ | ✅ |
| Opinion-grade verdicts | ❌ | ✅ | ✅ |
| Reform module | ❌ | ✅ | ✅ |
| Agent-native format | ❌ | ✅ | ✅ |
| Evidence retention | ❌ | ✅ | ✅ |
| Severity-based blocking | ❌ | ✅ | ✅ |
| Alerts (Slack/email) | ❌ | ✅ | ✅ |
| SSO | ❌ | ❌ | ✅ |
| Self-hosted | ❌ | ❌ | ✅ |
| Custom packs | ❌ | ❌ | ✅ |
| Governance integrations | ❌ | ❌ | ✅ |
| Support | Community | Standard | Named + SLA |

---

## Why NOT Per-Scan or Per-Seat

**Per-scan** penalizes the exact behavior we want (frequent CI checks, agent preflights before every merge). If scanning costs money, teams scan less. Less scanning = more violations shipped.

**Per-seat** breaks in the agent era. AI coding agents don't have headcounts. Autonomous PRs from agents should trigger compliance checks without counting as a "seat."

**Protected surface** aligns price to value: we're protecting your repos/pipelines from privacy-law violations. More repos = more value = more revenue. Scans are just how you realize that value.

---

## HoundDog / Privado Pricing Context

| | Free | Paid | Enterprise |
|---|---|---|---|
| **HoundDog** | $0 (limited) | $100/yr per dev | Custom |
| **Privado** | OSS scanner | $4,200/mo (200 devs) | Custom |
| **Clearway** | $0 (full CLI+MCP) | $99-199/mo per 5 repos | $15-50K+/yr |

See `docs/COMPETITIVE-LANDSCAPE.md` for detailed competitive analysis.