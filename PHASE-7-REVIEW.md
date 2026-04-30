# Phase 7 US CCPA/CPRA Jurisdiction Pack Review

Branch reviewed: `feature/us-ccpa-pack`  
Base: `cc887d6a732e8464f58c9404e0f26125028985f5`  
Head: `0e192f2662700403d3daac454cf220a0ba1e32df`

## Validation

- `git diff main...feature/us-ccpa-pack` reviewed.
- `npx tsc --noEmit` passed.
- `npx vitest run` passed: 25 files, 450 tests.
- An extra manual `npx tsx src/cli/index.ts ...` smoke was blocked by the local sandbox because `tsx` could not open its IPC pipe (`listen EPERM`). The requested `vitest` CLI coverage still passed.

## Findings

### C: CCPA CLI audit/compliance-check still use APP-only controls

`src/cli/index.ts:223-247` and `src/cli/index.ts:270-294` build a jurisdiction-aware report, but the agent/non-agent exit logic and terminal control summary still inspect `report.appControls`. For `--jurisdiction us-ccpa`, `buildComplianceReport` intentionally returns `appControls: []` and places the actual CCPA controls in `regulationControls`, so a CCPA audit can omit failed CCPA controls from the terminal summary and exit successfully for non-critical failed CCPA controls.

The same issue is larger in `compliance-check`: `src/cli/index.ts:376-426` passes `jurisdiction` into the report, but `src/report/smb-generator.ts:248-278` and `src/report/smb-generator.ts:342-359` only read `report.appControls`. A CCPA compliance check therefore has no evaluated controls, no CCPA actions, and an `unknown` SMB result even when `regulationControls` contains CCPA failures.

Recommended fix: centralize a `getReportControls`-style helper for CLI exit/status and either make SMB output explicitly AU-only with a clear rejection for `us-ccpa`, or teach the SMB generator to consume `regulationControls` with CCPA copy.

### C: The CCPA questionnaire bank is not actually reachable end-to-end

The new CCPA bank exists, but the attestation/session pipeline remains APP-only:

- `attest` has no `--jurisdiction` option (`src/cli/index.ts:305-327`).
- `executeAttestCommand` creates the orchestrator from options but no CCPA jurisdiction can be supplied (`src/cli/index.ts:1142-1177`).
- Questionnaire derivation calls `mapAllFindingsAU` only (`src/questionnaire/attest.ts:98-103`).
- Sessions only accept `APPPrinciple` values (`src/schema/index.ts:288-295`, `src/questionnaire/session.ts:473-485`).
- `getQuestionBankForJurisdiction('us-ccpa')` casts the CCPA bank to `Question[]`, but `getQuestionPrincipleOrder` orders only `APPInfo` keys, so CCPA principles produce no next question (`src/questionnaire/flow.ts:18-24`, `src/questionnaire/flow.ts:73-105`).

This means Phase 7 ships CCPA questions but not a working CCPA questionnaire-backed assessment. Recommended fix: make questionnaire sessions jurisdiction-aware, widen principle/session schemas to regulation principles, and add jurisdiction-aware attestation initialization/resume/hash validation.

### C: CCPA questionnaire logic and legal wording have material errors

The questionnaire has questions that either evaluate incorrectly or are legally stale/incomplete:

- `Q-CCPA125-001` asks whether the business discriminates against consumers who exercise rights, but marks it as `applicability_gate` with `passOn: 'no'` (`src/questionnaire/ccpa-questions.ts:65-73`). The evaluator returns `pass` for both sides of an applicability gate, so answering "yes, we discriminate" does not fail the control (`src/questionnaire/evaluator.ts:52-82`).
- `Q-CCPA145-001` uses `>$25M` (`src/questionnaire/ccpa-questions.ts:93-101`), but the CPPA adjusted the revenue threshold to `$26,625,000` effective January 1, 2025. Its `passOn: 'no'` also treats "not applicable" as the compliant answer while the same evaluator still passes "yes"; this should be modeled as applicability metadata, not a compliance control result.
- `Q-CCPA130-001` says "all 11 required categories" (`src/questionnaire/ccpa-questions.ts:75-82`), but current Civil Code section 1798.130 requires privacy-policy disclosures across consumer rights, designated methods, collected categories, source categories, purposes, disclosed third-party categories, sale/share lists, business-purpose disclosure lists, and sensitive PI categories. Reducing it to 11 categories misses material 1798.130 content.

Recommended fix: add questionnaire tests that answer both pass/fail paths for each CCPA question, update thresholds, and split applicability gates from control scoring.

### C: CCPA scanner rules are legally overbroad and cite the wrong operative sections

`scanCcpaChecks` emits missing Do Not Sell, Limit Sensitive PI, and GPC findings for any repository with a web surface (`src/scanner/rules/ccpa-checks.ts:127-152`). The rules do not first establish that the business sells/shares PI, uses/discloses sensitive PI outside section 1798.121(a), targets California consumers, or has chosen the link path instead of the opt-out preference signal path.

The citations are also too loose:

- The homepage link requirements live in Civil Code section 1798.135(a)(1)-(3), not primarily sections 1798.120/1798.121 (`src/scanner/rules/ccpa-checks.ts:26-50`).
- GPC processing is detailed in 11 CCR section 7025 and Civil Code section 1798.135(b), not just a generic section 1798.135 citation (`src/scanner/rules/ccpa-checks.ts:85-98`).
- The CCPA_150 copy still reports `$100-$750` (`src/scanner/rules/ccpa-principles.ts:59-62`), while CPPA's 2025 CPI adjustment lists `$107-$799`.

Recommended fix: make these rules conditional or downgrade confidence/status to `unknown` unless applicability signals exist, use section 1798.135 for required links, cite 11 CCR section 7025 for opt-out preference signals, and update CPI-adjusted amounts.

### C/T: MCP CCPA contracts are partially inconsistent

The MCP scan handlers can return CCPA controls with `{ jurisdiction: 'us-ccpa', principle: 'CCPA_100' }` (`src/mcp/index.ts:749-780`), but the registered output schema still declares `controls[].principle` and `summary.affectedPrinciples` as `APPPrinciple` and omits `jurisdiction` (`src/mcp/index.ts:273-294`). MCP clients using the advertised schema can reject or misinterpret valid CCPA responses.

Separately, `attestlens_map` has no jurisdiction input and always maps with `jurisdictions: ['au-privacy-act']` (`src/mcp/index.ts:187-199`, `src/mcp/index.ts:999-1003`). That leaves no MCP path to map supplied findings directly to CCPA without running a scan.

Recommended fix: make the scan output schema use `RegulationPrinciple` plus `jurisdiction`, add CCPA coverage for schema validation through the registered server path, and add a jurisdiction argument to `attestlens_map`.

### T: Missing coverage for non-empty CCPA end-to-end paths

The new tests prove CCPA is accepted and that simple mapping/report generation can work, but they miss the failure modes above. Add coverage for:

- CLI `audit --jurisdiction us-ccpa` with non-critical CCPA failures, asserting CCPA controls print and non-zero exit behavior is based on `regulationControls`.
- CLI `compliance-check --jurisdiction us-ccpa` with CCPA findings, asserting the result is not `Unknown` solely because `appControls` is empty.
- `attest` or equivalent CCPA questionnaire flow, including session save/load and resume.
- `report` command regeneration from saved CCPA scan/report data, with jurisdiction inference or an explicit jurisdiction flag.
- MCP registered output schema validation for `us-ccpa`, not only direct `handleToolCall` payload inspection.
- Negative legal/applicability cases: no sale/share, no sensitive PI additional use, GPC-only compliance, and updated 2025 CPPA CPI thresholds.

## Security Notes

No new `S` severity vulnerability was identified in the Phase 7 diff. Existing MCP path validation continues to canonicalize allowed roots and reject symlink escapes; scanner execution still uses `execFile` rather than shell interpolation; report generation continues to sanitize target path/URL output. The main risks found are correctness/legal-contract issues rather than injection, unauthorized access, or data leakage.

## Backward Compatibility

Default AU behavior remains the default across CLI, MCP, scanner orchestration, mapping, and report generation. The full test suite passes, including existing AU questionnaire/report tests. The CCPA changes do not appear to make `eu-gdpr` available; CLI/MCP availability checks still reject it, and loader tests assert the unavailable pack behavior.

## Legal Sources Checked

- California Civil Code section 1798.100: https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1798.100
- California Civil Code section 1798.130: https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1798.130
- California Civil Code section 1798.135: https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1798.135
- California Civil Code section 1798.140: https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1798.140
- California Civil Code section 1798.150: https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1798.150
- California Code of Regulations, title 11, section 7025: https://www.law.cornell.edu/regulations/california/11-CCR-7025
- CPPA 2025 CPI threshold adjustments: https://cppa.ca.gov/regulations/cpi_adjustment.html
