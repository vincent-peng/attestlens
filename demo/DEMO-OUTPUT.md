# Multi-Jurisdiction Demo Output

Expected sample output from:

```bash
bash demo/multi-jurisdiction.sh
```

Scores can move as rule packs improve. The important demo property is stable:
the same generated project is scanned three times, and each jurisdiction cites a
different legal surface with different remediation.

```text
Clearway multi-jurisdiction demo
Demo project: /tmp/tmp.xxxxxx/demo-project

$ npx @attestlens/cli audit ./demo-project --jurisdiction au-privacy-act --opinion --format agent
$ npx @attestlens/cli audit ./demo-project --jurisdiction us-ccpa --opinion --format agent
$ npx @attestlens/cli audit ./demo-project --jurisdiction eu-gdpr --opinion --format agent

=== AU Privacy Act ===
Command exit: 1 (non-zero is expected for NON_COMPLIANT agent output)
Verdict: NON_COMPLIANT | confidence: LOW | score: 81 | risk: critical
Summary: NON COMPLIANT - 3 of 14 principles non-compliant
Cited controls and remediations:
- APP_6 (APP Guidelines Chapter 6.1): NON_COMPLIANT; Restrict CORS to specific allowed origins. Never use * in production.
- APP_11 (APP Guidelines Chapter 11.1): NON_COMPLIANT; Move secrets to environment variables (.env.local, not committed). Add to .gitignore.

=== US CCPA/CPRA ===
Command exit: 1 (non-zero is expected for NON_COMPLIANT agent output)
Verdict: NON_COMPLIANT | confidence: LOW | score: 90 | risk: critical
Summary: NON COMPLIANT - 3 of 12 principles non-compliant
Cited controls and remediations:
- CCPA_100 (Cal. Civ. Code §1798.100): NON_COMPLIANT; Move secrets to environment variables (.env.local, not committed). Add to .gitignore.
- CCPA_120 (Cal. Civ. Code §1798.120): UNKNOWN; Add a clear "Do Not Sell or Share My Personal Information" link where CCPA opt-out rights must be presented.
- CCPA_135 (Cal. Civ. Code §1798.135): UNKNOWN; Honor navigator.globalPrivacyControl as a valid opt-out signal where CCPA opt-out obligations apply.

=== EU GDPR ===
Command exit: 1 (non-zero is expected for NON_COMPLIANT agent output)
Verdict: NON_COMPLIANT | confidence: LOW | score: 93 | risk: critical
Summary: NON COMPLIANT - 1 of 14 principles non-compliant
Cited controls and remediations:
- GDPR_Art5 (GDPR Art. 5): UNKNOWN; Confirm collection is necessary and add consent, notice, or lawful-basis checks where required.
- GDPR_Art32 (GDPR Art. 32): NON_COMPLIANT; Move secrets to environment variables (.env.local, not committed). Add to .gitignore.
- GDPR_Art44 (GDPR Art. 44-49): UNKNOWN; Document the transfer mechanism for data sent outside the EEA, such as adequacy decision, SCCs, BCRs, or another Art 44-49 safeguard.

Same demo project, three different compliance realities.
```

## What The Demo Fixture Contains

| File | Intentional issue | Jurisdiction signal |
| --- | --- | --- |
| `privacy-policy.html` | Privacy policy omits Do Not Sell and CCPA/GDPR disclosures | CCPA §1798.120, §1798.135, §1798.130; GDPR Art. 13 |
| `config.json` | Overseas transfer enabled without transfer safeguards | GDPR Art. 44-49 |
| `package.json` | No privacy-policy homepage link | AU transparency/disclosure review context |
| `Dockerfile` | Container explicitly runs as root | APP 11 and security-of-processing context |
| `server.js` | Logs email addresses and auth token fields, uses wildcard CORS, contains demo secret | APP 6, APP 11, CCPA §1798.100, GDPR Art. 5, GDPR Art. 32 |

## Raw Agent Shape

Each audit command returns `attestlens-agent-v1` JSON:

```json
{
  "schema": "attestlens-agent-v1",
  "verdict": "NON_COMPLIANT",
  "confidence": "LOW",
  "score": 90,
  "riskLevel": "critical",
  "actions": [
    {
      "principle": "CCPA_120",
      "verdict": "UNKNOWN",
      "score": 90,
      "action": "Provide evidence for Right to Opt-Out",
      "remediation": "Add a clear \"Do Not Sell or Share My Personal Information\" link where CCPA opt-out rights must be presented."
    }
  ],
  "summary": "NON COMPLIANT - 3 of 12 principles non-compliant"
}
```
