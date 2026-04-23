# Attestation Review

- Run date: {{RUN_DATE}}
- Scenario: {{SCENARIO_LABEL}} (`{{SCENARIO_ID}}`)
- Lane: {{SCENARIO_TYPE}}
- Review goal: {{REVIEW_GOAL}}
- Focus principles: {{FOCUS_PRINCIPLES}}
- Expected outcome pattern: {{EXPECTED_OUTCOME_PATTERN}}
- Scan source: {{SCAN_SOURCE}}
- Recommended assessment mode: {{RECOMMENDED_ASSESSMENT_MODE}}
- Sanitized target label: {{SANITIZED_LABEL}}
- Operator context file: {{OPERATOR_CONTEXT_FILE}}

## Operator Assumptions

{{OPERATOR_ASSUMPTIONS}}

## Execution Notes

- Command run:
- Session path:
- Report paths:
- Anything that blocked or slowed the run:

## Review Rubric

### Resolution Quality

- Resolved principles count:
- Unresolved principles that should have resolved:
- Principles that resolved but should have remained unknown:

### Failure Quality

- False pass count:
- False fail count:
- Any P1/P2 misleading outcome:

### Question Quality

- Awkward or ambiguous questions:
- Branches that felt inapplicable or redundant:
- Evidence-note usefulness:

### Report Quality

- Report usefulness (1-5):
- What a consultant/operator would still need to rewrite manually:
- Anything misleading in the merged summary:

## Follow-up Patch Notes

- `keep`
- `reword`
- `reclassify`
- `new gate`
- `new evidence-only question`

## Sanitized Log Row Draft

| Date | Scenario | Lane | Sanitized Target Label | Scan Source | Resolved Principles | Unresolved That Should Resolve | False Passes | False Fails | Awkward Questions | Report Usefulness (1-5) | Follow-up Patch Notes |
|---|---|---|---|---|---|---|---:|---:|---|---:|---|
| {{RUN_DATE}} | {{SCENARIO_ID}} | {{SCENARIO_TYPE}} |  | {{SCAN_SOURCE}} |  |  | 0 | 0 |  |  |  |
