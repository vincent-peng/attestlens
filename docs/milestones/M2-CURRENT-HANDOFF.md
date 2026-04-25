# M2 Current Handoff

**Last Updated:** 2026-04-24  
**Purpose:** Quick pickup note for the next developer working on M2.

---

## Current State

M2 foundation is now in place:

- questionnaire-backed `attest` workflow exists
- sessions persist to JSON and can resume
- per-session question sets are frozen
- merged reports combine scan evidence with questionnaire outcomes
- attestation validation workflow exists and has already been exercised across 3 public scenarios plus 1 sanitized private dry run

The latest correctness follow-up also landed:

- pre-`1.3` sessions now require an explicit assessment basis on first resume
- known `m2-coverage-v1` `1.2` sessions upgrade onto `1.3` using their stored questionnaire bank
- APP 5 direct notice now uses an APP 5-local gate instead of depending on APP 3
- evidence-limited merged reports now carry `assessment` metadata and no longer surface as `A / low-risk`
- `attest --assessment-mode` exists and validation scenarios now freeze recommended modes

The M2 closeout implementation is now in place:

- breach-readiness scoring is additive to the existing overall score/grade/risk fields
- consultant-facing deterministic narrative sections render in report outputs
- GuardVibe fallback and orchestrator tests use deterministic temp fixtures
- `AL-INFRA-006` now requires stronger WordPress-login evidence and has regression coverage

The first M2.5 pickup slice has also started:

- M2 was published to `origin/main` at `4e5cb31`
- design-partner feedback now has one tracking file at `docs/validation/DESIGN-PARTNER-VALIDATION.md`
- rule-pack manifest and freshness metadata exist
- `attestlens update-rules` can refresh the local rule cache from local/HTTPS JSON sources, and no-source runs preserve an existing cache or seed embedded rules when missing
- `--auto-update` is opt-in and source-gated so scans do not overwrite a newer cache with embedded rules
- scan, audit, attest snapshots, MCP output, and reports can carry rule freshness metadata without exposing local cache paths
- Allowlisted GuardVibe fallback static regex rules are the first executable rule-pack family; active packs can override metadata or disable those rules, but active regex changes fall back visibly to embedded rules. URL/header/key/JS and repo-stack entries remain metadata-only until their runtime semantics are explicitly migrated

---

## Verified In This State

These commands passed on 2026-04-24:

- `npm test -- src/scanner/guardvibe.test.ts src/scanner/orchestrator.test.ts`
- `npm test -- src/report/generator.test.ts src/cli/index.test.ts src/schema/index.test.ts`
- `npm test -- src/scanner/url-scan.test.ts`
- `npm test`
- `npm run lint`
- `npm run build`

Run the full verification suite again after any further report or scanner-rule changes.

---

## Key Files

Questionnaire / attestation:

- `src/questionnaire/questions.ts`
- `src/questionnaire/session.ts`
- `src/questionnaire/evaluator.ts`
- `src/questionnaire/attest.ts`
- `src/cli/index.ts`

Reporting:

- `src/report/generator.ts`
- `src/schema/index.ts`

Validation workflow:

- `src/validation/attest.ts`
- `docs/validation/attest-scenarios.yaml`
- `docs/validation/ATTESTATION-LOG.md`

Project tracking:

- `docs/STATUS.md`
- `docs/ROADMAP.md`

---

## Remaining M2 Work

1. Keep the closeout verification suite green.
2. Use the refreshed sample reports for design-partner review.
3. Treat future corpus findings as routine rule-tuning follow-up rather than unresolved M2 foundation work.
4. Do not broaden M2.5 beyond compatibility-first rule freshness until design-partner feedback does not expose M2 report-shape blockers.

---

## Suggested Pickup Order

1. Run `npm test`, `npm run lint`, and `npm run build`.
2. Review refreshed Juice Shop sample report output.
3. Log external feedback in `docs/validation/DESIGN-PARTNER-VALIDATION.md`.
4. Continue M2.5 by deciding the next executable rule family only after report-shape feedback is clean.
