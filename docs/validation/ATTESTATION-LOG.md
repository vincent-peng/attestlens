# Attestation Validation Log

Track completed questionnaire-review runs here. Public scenarios may use their scenario name directly; private scenarios must use sanitized labels only.

| Date | Scenario | Lane | Sanitized Target Label | Scan Source | Resolved Principles | Unresolved That Should Resolve | False Passes | False Fails | Awkward Questions | Report Usefulness (1-5) | Follow-up Patch Notes |
|---|---|---|---|---|---|---|---:|---:|---|---:|---|
| 2026-04-23 | example-baseline | public | Example Baseline | corpus report | 13 | 0 | 0 | 7 | APP3/5 applicability; APP10/12/NDB certainty | 2 | reclassify APP_3/APP_5 public-site branches; new collection gate; report layout |
| 2026-04-23 | vercel-marketing | public | Vercel Marketing | corpus report | 13 | 0 | 0 | 6 | APP7 artifact-only basis; APP8 guesswork; APP3/5 applicability | 3 | reword APP_7 guidance; new collection gate; AL-INFRA-006 cleanup |
| 2026-04-23 | juice-shop-demo | public | Juice Shop Demo | corpus report | 13 | 0 | 0 | 3 | APP6/8 governance guesswork; APP2 branch still speculative | 3 | reclassify APP_8 artifact branch; severe-scan-first report ordering |
| 2026-04-23 | private-consultant-dry-run | private | Internal SaaS #1 | local scan | 11 | 0 | 0 | 5 | repo-only target context; APP11 split signal; access/NDB certainty | 2 | new target-context gate; report assumption labeling; reclassify access/NDB |

## Post-Remediation Replay

Replay basis: the saved 2026-04-23 scenario answers were re-evaluated against the remediated questionnaire logic using frozen replay modes (`artifact_only` for the three public scenarios and `codebase_only` for the sanitized private dry run).

| Date | Scenario | Replay Basis | Outcome Shift | Remaining Notes |
|---|---|---|---|---|
| 2026-04-23 | example-baseline | artifact_only | APP 3 and APP 5 now resolve as `PASS` for the reviewed surface; APP 6 / 7 / 8 / 10 / 12 / NDB now stay `UNKNOWN` instead of false-failing from missing operator evidence. | APP 1 and APP 13 still depend on what the public artifact visibly discloses. |
| 2026-04-23 | vercel-marketing | artifact_only | APP 3 and APP 5 now resolve as `PASS` for the reviewed surface; APP 6 / 7 / 8 / 10 / 12 / NDB now stay `UNKNOWN` instead of false-failing from missing operator evidence. | `AL-INFRA-006` remains validation noise in the saved corpus artifact. |
| 2026-04-23 | juice-shop-demo | artifact_only | Governance-heavy branches now stay `UNKNOWN` without operator evidence; APP 3 / APP 5 still fail when direct collection is clearly in scope on the reviewed surface. | APP 2 remains the main speculative branch on a high-interaction public demo surface. |
| 2026-04-23 | private-consultant-dry-run | codebase_only | Repo-only replay no longer forces live-service governance fails; APP 7 / 8 / 10 / 12 now stay `UNKNOWN`, and the report now labels codebase-only evidence plus scanner-derived APP 11 findings separately. | Further report polish can wait for consultant-facing narrative sections. |

Fixed in the remediation patch:

- P1 APP 3 / APP 5 direct-collection false fails on saved public artifacts
- P2 APP 6 / APP 10 / APP 12 / NDB false fails from artifact-only or codebase-only context
- P2 APP 11 report clarity gap between scanner-derived evidence and questionnaire-backed assumptions
- P2 repo-only dry-run context handling for codebase-only validation

Fixed in the 2026-04-24 correctness follow-up:

- P1 known pre-remediation `1.2` attestation sessions now upgrade onto `1.3` using their stored questionnaire bank instead of failing closed
- P1 evidence-limited merged reports no longer present `A / low-risk` summaries while controls remain unresolved
- P1 APP 5 direct-notice branch is reachable in `APP_5`-only sessions
- P2 validation commands now freeze the scenario-recommended assessment basis via `--assessment-mode`

## Remaining Follow-up Queue

| Severity | Type | Affected Scenarios | Symptom | Recommended Fix Type |
|---|---|---|---|---|
| P3 | scanner-noise issue | vercel-marketing | `AL-INFRA-006` WordPress admin detection still reads as validation noise in the saved Vercel artifact. | rule cleanup |

No P1 false-pass outcome was observed in the first validation cycle, the post-remediation replay, or the 2026-04-24 correctness follow-up.
