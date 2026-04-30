# Design Partner Strategy

## Target

3-5 Australian SMEs facing July 2026 Privacy Act obligations.

Primary fit:

- Has a real software product, website, or internal application with personal information flows.
- Expects to fall under Privacy Act obligations by July 2026.
- Needs a practical compliance starting point before paying for a full legal review.
- Can share code, scan output, or a sanitized findings export under agreed confidentiality.

## Offer

Free compliance audit, opinion, and ongoing monitoring for the feedback period.

Deliverables:

- Initial Clearway scan across AU Privacy Act obligations.
- Opinion-grade compliance verdict with evidence and remediation priorities.
- SMB compliance-check report where the business profile fits.
- Follow-up scan after fixes.
- Optional US CCPA/CPRA or EU GDPR comparison if the business sells into those markets.

## Ask

Structured feedback on:

- Report clarity: Can a founder or operator understand what failed and why?
- Verdict accuracy: Does the opinion match the team's real system and compliance posture?
- Remediation usefulness: Are the suggested fixes specific enough to act on?
- Workflow fit: Does CLI, MCP, or CI integration match how the team ships?
- Trust boundary: What evidence would make them comfortable gating deployments on Clearway?

## Timeline

4-6 weeks of feedback before npm publish.

Suggested cadence:

| Week | Activity |
| --- | --- |
| 1 | Recruit and qualify 3-5 partners. Run baseline scans. |
| 2 | Review reports live with each partner. Capture unclear language and false positives. |
| 3 | Partners attempt first remediation pass. Clearway tracks before/after changes. |
| 4 | Run follow-up scans. Validate verdict movement and remediation usefulness. |
| 5 | Consolidate product feedback and fix high-signal report or scanner issues. |
| 6 | Final publish-readiness review and partner quotes, if approved. |

## Selection Criteria

Must-have:

- Has a codebase or URL Clearway can scan.
- Is under, or expects to be under, Privacy Act obligations.
- Is willing to share findings and feedback.
- Has someone who can validate whether remediation advice is technically feasible.

Prefer:

- Handles customer accounts, support messages, bookings, payments, health, identity, or other personal information.
- Operates in Australia with possible US or EU customer exposure.
- Ships frequently enough that CI or agent-native compliance checks matter.
- Has a founder/operator who will review the report directly.

Avoid for the first cohort:

- Businesses with no software surface to scan.
- Enterprises with procurement cycles that slow feedback.
- Heavily regulated edge cases that need specialist legal interpretation before product feedback is useful.
- Teams unwilling to share even sanitized findings.

## Success Criteria

- At least 3 partners complete initial scan and feedback.
- At least 2 partners complete a remediation and re-scan loop.
- Clear report language issues are fixed before npm publish.
- False positives or confusing jurisdiction mappings are logged with reproducible fixtures.
- At least 1 partner says they would run Clearway again in CI, MCP, or a release checklist.
