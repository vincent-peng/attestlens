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

---

## Verified In This State

These commands passed on 2026-04-24:

- `npm test -- src/questionnaire/index.test.ts src/cli/index.test.ts src/report/generator.test.ts src/validation/attest.test.ts`
- `npm run lint`
- `npm run build`

Full `npm test` is **not** green yet.

Known unrelated failures still present:

- `src/scanner/guardvibe.test.ts`
  - static fallback findings for `VS-HARDKEY`, `VS-XSS`, `VS-DEBUG`, and `VS-ENV` are returning `0`
- `src/scanner/orchestrator.test.ts`
  - `should return findings from scan` fails because the GuardVibe fallback returns `0` findings

Treat those as the current engineering cleanup item, not as unresolved M2 questionnaire/report correctness work.

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

1. Add breach-readiness scoring on top of the current merged report baseline.
2. Add consultant-facing narrative sections once scoring lands.
3. Clean up the remaining validation noise:
   - `AL-INFRA-006` in the saved Vercel artifact
4. Restore a fully green `npm test` by fixing the GuardVibe static-fallback regression.

---

## Suggested Pickup Order

1. Fix the GuardVibe static-fallback regression so the full suite is green again.
2. Implement breach-readiness scoring using the new `assessment` metadata and incomplete-assessment rules.
3. Add consultant-facing report narratives after the scoring model is stable.
4. Re-run the attestation validation scenarios if scoring or report structure meaningfully changes.
