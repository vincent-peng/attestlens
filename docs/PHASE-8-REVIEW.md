# Phase 8 Code Review & Security Audit

Branch: `feature/eu-gdpr-pack`  
Reviewed commit: `2c69f65`  
Review date: 2026-04-30  
Legal baseline: Regulation (EU) 2016/679 official text, especially Articles 3, 9, 33, 35, and 44-49: <https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32016R0679>

## Summary

The EU GDPR subset pack is broadly integrated: schema, embedded pack loading, CLI/MCP jurisdiction parsing, report scope notes, scanner rules, questionnaire bank, and mapping rules are present. Focused Phase 8 tests passed, the full suite passed, and TypeScript checking passed.

There are still review-blocking issues before treating the GDPR pack as production-quality compliance output:

- One security issue can leak special-category values into generated reports.
- One correctness issue causes advisory GDPR scanner findings to suppress the exact questionnaire follow-up needed to resolve them.
- Several legal-modeling issues need tightening for Article 3, Article 9, and Article 33.

## Security Findings

### S-001: GDPR-SEC-001 stores and renders raw special-category values

Severity: High  
Files:

- `src/scanner/rules/gdpr-checks.ts:179-190`
- `src/scanner/rules/gdpr-checks.ts:224-235`
- `src/scanner/rules/gdpr-checks.ts:252-258`
- `src/report/generator.ts:1168-1171`

`GDPR-SEC-001` detects plaintext special-category data, then stores the entire matched source line in `finding.code`. Report generation renders `f.code` into HTML and other formats. If a repository contains `health_condition: "asthma"` or a biometric fixture value, the audit report can reproduce the sensitive value.

This is an information-disclosure path introduced by the GDPR scanner. Escaping HTML prevents script injection, but it does not prevent privacy leakage into JSON, HTML, Markdown, PDF, agent output, logs, or artifacts.

Recommendation:

- Redact values before assigning `finding.code`, for example `health_condition: [REDACTED]`.
- Preserve file, line, rule id, and field/key name so the finding stays actionable.
- Add regression tests proving raw special-category values do not appear in any generated report format.

## Correctness Findings

### C-001: Advisory GDPR findings suppress the questionnaire follow-up that should resolve them

Severity: High  
Files:

- `src/scanner/rules/gdpr-checks.ts:31-117`
- `src/mapping/engine.ts:1545-1554`
- `src/questionnaire/attest.ts:104-115`

The negative-detection GDPR scanner rules correctly map to `status: 'unknown'` with `confidence: 0.5`. However, `mapAllFindings()` clears `questionnaireRequired` for any control with findings, even when the control remains `unknown`. `deriveQuestionnairePrinciples()` then only returns controls where `questionnaireRequired` is true.

Impact examples:

- `GDPR-CONSENT-001` creates an unknown Art. 6 finding, then Art. 6 is not asked.
- `GDPR-TRANSFER-001` creates an unknown Art. 44 finding, then the Art. 44 transfer gate is not asked.
- `GDPR-ART22-001` creates an unknown Art. 22 finding, then the Art. 22 automated-decision gate is not asked.

That undercuts the intended advisory workflow: these rules should route the user into attestation, not block the relevant attestation question.

Recommendation:

- Keep `questionnaireRequired = true` for `unknown` controls with advisory findings, or add an explicit advisory mapping flag that preserves questionnaire routing.
- Add tests for `deriveQuestionnairePrinciples(findings, 'eu-gdpr')` using `GDPR-CONSENT-001`, `GDPR-TRANSFER-001`, `GDPR-DPIA-001`, and `GDPR-ART22-001`.

### C-002: Article 3 applicability wording is legally overbroad and misses the actual triggers

Severity: Medium  
Files:

- `src/scanner/rules/gdpr-principles.ts:4-8`
- `src/questionnaire/gdpr-questions.ts:10-18`
- `docs/JURISDICTION-RESEARCH.md:76`

The current wording says GDPR applies if processing "EU residents' data" regardless of processor location. Article 3 is more specific:

- Establishment in the Union can bring processing into scope.
- For controllers/processors outside the Union, extra-territorial scope turns on data subjects in the Union plus offering goods/services or monitoring behavior.

"EU residents" is also narrower/different than "data subjects who are in the Union."

Recommendation:

- Replace the single Art. 3 gate with clearer establishment/offering/monitoring wording, or split it into multiple applicability gates.
- Avoid saying GDPR applies to all EU-resident data regardless of the processing context.

### C-003: Article 9 special-category coverage is incomplete

Severity: Medium  
Files:

- `src/scanner/rules/gdpr-principles.ts:19-22`
- `src/questionnaire/gdpr-questions.ts:47-60`
- `src/scanner/rules/gdpr-checks.ts:108-117`
- `src/scanner/rules/gdpr-checks.ts:140`

The principle description, questionnaire wording, and scanner pattern cover some special categories, but omit or understate several Article 9 categories, including political opinions, philosophical beliefs, trade union membership, genetic data, and sex life.

Recommendation:

- Expand the Art. 9 principle description and questionnaire copy to reflect the full Art. 9 taxonomy.
- Extend `SPECIAL_CATEGORY_PATTERN` and tests for representative keys such as `political_opinion`, `trade_union_member`, `genetic_data`, `philosophical_belief`, and `sex_life`.

### C-004: MAP-GDPR-006 treats generic breach/leak/exposure categories as an Article 33 failure

Severity: Medium  
File: `src/mapping/engine.ts:1147-1157`

`MAP-GDPR-006` maps any `breach|leak|expos` category to `GDPR_Art33` with `status: 'fail'`. Article 33 is about notifying the supervisory authority after becoming aware of a personal data breach, subject to risk assessment. A vulnerability, leak-like finding category, or exposure pathway does not prove the organization failed to notify.

Recommendation:

- Change this mapping to `status: 'unknown'` unless the finding explicitly establishes an actual personal-data breach and missed notification process.
- Keep the rationale as an assessment trigger rather than a failure conclusion.

## Quality Findings

### Q-001: `getJurisdictionUnavailableMessage()` is now misleading as an error message

Severity: Low  
Files:

- `src/scanner/rules/loader.ts:383-384`
- `src/scanner/orchestrator.ts:544-558`
- `src/scanner/rules/loader.test.ts:315-318`

The helper now returns `All jurisdictions are available: au-privacy-act, us-ccpa, eu-gdpr. Requested jurisdiction: ...`. That is true as a support statement, but it is still used by the orchestrator as the thrown error when a requested pack is missing or marked unavailable.

Normal CLI/MCP paths should not hit this for supported jurisdictions, but if a pack-load regression occurs the failure text will contradict the condition that triggered it.

Recommendation:

- Rename or retire this helper, or change it to a pack-load failure message such as `No embedded rule pack loaded for requested jurisdiction: ...`.
- Keep the "all declared jurisdictions are available" assertion in tests, but do not assert that phrase as the runtime unavailable message.

### Q-002: Documentation references a nonexistent `GDPR_Art14` principle ID

Severity: Low  
Files:

- `docs/JURISDICTION-RESEARCH.md:74-89`
- `src/schema/index.ts:112-127`

The schema defines 14 GDPR principle IDs and intentionally folds Art. 13-14 into `GDPR_Art13`. The jurisdiction research table lists `GDPR_Art13` / `GDPR_Art14`, but `GDPR_Art14` does not exist.

Recommendation:

- Update the table to `GDPR_Art13` with a note that it covers Art. 13-14 in this subset model.
- Prefer "14 principle IDs covering selected articles/article ranges" over "14 articles", because Art. 13-14, Art. 33-34, and Art. 44-49 are ranges or paired obligations.

## Testing Findings

### T-001: Add questionnaire-routing regression tests for advisory GDPR findings

Severity: High  
Related finding: C-001

Existing tests cover the presence and mapping shape of GDPR scanner rules, but they do not catch the interaction where an unknown advisory finding suppresses the relevant attestation question.

Add tests that verify:

- `GDPR-CONSENT-001` routes to `GDPR_Art6`.
- `GDPR-TRANSFER-001` routes to `GDPR_Art44`.
- `GDPR-DPIA-001` routes to `GDPR_Art35`.
- `GDPR-ART22-001` routes to `GDPR_Art22`.

### T-002: Add redaction tests for special-category scanner findings and reports

Severity: High  
Related finding: S-001

Add tests using a fixture such as `health_condition: "asthma"` and assert:

- The scanner emits `GDPR-SEC-001`.
- `finding.code` does not contain the sensitive value.
- JSON, HTML, Markdown, and PDF/agent report outputs do not contain the sensitive value.
- File and line evidence remain present.

## Review Focus Answers

1. Legal accuracy: Partially correct. Report scope labels are present, but Art. 3 is overbroad, Art. 9 is incomplete, and Art. 33 mapping overstates failure from generic leak/exposure categories.
2. Security: No regex-injection issue found; patterns are fixed constants and line-scoped. S-001 is the material security issue because raw special-category values are persisted and rendered.
3. Applicability gates: The four gates use `role: 'applicability_gate'` and `passOn: 'no'` for Art. 3, Art. 9, Art. 22, and Art. 44. The Art. 3 wording needs legal correction.
4. Advisory rules: Confirmed. Negative-detection rules use `status: 'unknown'` and `confidence: 0.5`; `GDPR-SEC-001` uses fail semantics with `confidence: 0.85`.
5. Backward compatibility: Confirmed by the full suite: 497 tests passed.
6. Fail-closed: Pack loading is fail-closed in the orchestrator because packs load before scanning and `assertJurisdictionPacksAvailable()` throws when a requested pack is missing. Runtime stack-check exceptions are still swallowed by the existing static-fallback path, but that is separate from pack-load failure.
7. Questionnaire evaluation: `eu-gdpr` is wired through the question bank and principle ordering, but C-001 means advisory GDPR findings can prevent the correct GDPR questionnaire items from being asked.
8. `compliance-check` rejection: Confirmed. CLI rejects non-AU jurisdictions with `SMB compliance check is currently AU-only; use audit --jurisdiction eu-gdpr for EU GDPR assessments.`
9. Scope boundaries: Reports explicitly state the GDPR subset scope. Docs mostly do, but should fix the nonexistent `GDPR_Art14` reference and use "14 principle IDs" rather than "14 articles."
10. Loader cleanup: Removing `buildUnavailableRulePack` and `buildUnavailableJurisdictionPack` appears safe. `rg` found no remaining callers.
11. `getJurisdictionUnavailableMessage`: The new message is not correct as an error message. It is not expected on normal supported paths, but it should be changed before relying on it for diagnostics.

## Validation Performed

```bash
pnpm exec vitest run src/scanner/rules/gdpr-checks.test.ts src/scanner/rules/loader.test.ts src/questionnaire/index.test.ts src/mapping/engine.test.ts src/cli/index.test.ts src/mcp/index.test.ts src/report/generator.test.ts src/scanner/orchestrator.test.ts
```

Result: 8 test files, 272 tests passed.

```bash
pnpm test
```

Result: 26 test files, 497 tests passed.

```bash
pnpm run lint
```

Result: TypeScript `tsc --noEmit` passed.

```bash
git diff --check HEAD^ HEAD
```

Result: passed.
