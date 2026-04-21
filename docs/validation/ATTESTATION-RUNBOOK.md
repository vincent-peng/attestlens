# Attestation Validation Runbook

This workflow validates the `attest` questionnaire and merged report path without adding a new product surface.

## Goal

Use a small hybrid lane to answer three questions:

1. Does the questionnaire resolve the right principles?
2. Does it avoid false pass/fail outcomes on realistic branches?
3. Does the merged report feel useful to a consultant or privacy operator?

## Lanes

### Public lane

Use reproducible saved corpus artifacts, not live rescans.

Rules:

- Prepare the run with `npm run validate:attest -- <scenario-id>`
- The helper resolves the latest saved corpus JSON under `attestlens-reports/validation/...`
- Complete the questionnaire with `attest --from-scan`
- Use only:
  - the saved scan/report artifact
  - the scenario assumptions in `attest-scenarios.yaml`
  - obvious public context already implied by the saved artifact
- Do not invent internal governance or policy facts
- If an answer requires knowledge you do not have, answer conservatively and record the awkwardness

### Private lane

Use a real non-public repo or app, but keep committed output sanitized.

Rules:

- Prepare the run with:
  - `npm run validate:attest -- private-consultant-dry-run --target <path-or-url> --name <label>`
  - or `--from-scan <json> --name <label>`
- Raw artifacts stay local under `attestlens-reports/attest-validation/...`
- Only sanitized summaries go into `ATTESTATION-LOG.md`
- Do not commit customer names, raw paths, raw URLs, or local artifact locations

## Review Process

1. Run the helper script and open the generated `REVIEW.md`
2. Run the generated `attest` command from `COMMAND.txt`
3. Complete the questionnaire honestly and conservatively
4. Fill in the rubric sections in `REVIEW.md`
5. Copy a sanitized summary row into `ATTESTATION-LOG.md`
6. Turn repeated issues into a short patch list for questionnaire/report refinement

## Review Rubric

Every run should score:

- resolved principles count
- unresolved principles that should have resolved
- principles that resolved but should have remained unknown
- false pass count
- false fail count
- awkward or ambiguous questions
- evidence-note usefulness
- report usefulness (1-5)
- follow-up patch notes

## Exit Gate For This Slice

The attestation validation workflow is considered landed when:

- all three public scenarios have completed review rows in `ATTESTATION-LOG.md`
- at least one private/internal dry run has been logged in sanitized form
- each run has a completed `REVIEW.md`
- the resulting issues are triaged into a short patch list
- no known P1 false-pass outcome remains unaddressed in the notes
