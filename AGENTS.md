# AGENTS.md

Guidance for coding agents working in this repository. This file applies to the
entire repo unless a more specific `AGENTS.md` appears in a subdirectory.

## Project

Clearway by AttestLens is a deterministic compliance runtime for AI agents. It
scans codebases and URLs for privacy law compliance violations across supported
jurisdictions, currently AU Privacy Act, US CCPA/CPRA, and an EU GDPR subset.

The product ships as:

- CLI package: `@attestlens/cli`
- MCP server: `attestlens-mcp`
- npm package for agent-native compliance workflows

Current baseline from `docs/STATUS.md`: v0.3.0, 3 jurisdiction packs, 8 MCP
tools, opinion-grade assessments, SMB compliance workflow, 502 tests, and
`tsc --noEmit` clean. Keep claims conservative: say "multi-jurisdiction", not
"global", until jurisdiction packs have external legal validation.

## Build And Test

Run these commands from the repository root:

```bash
npx tsc --noEmit
npx vitest run
npm run lint
npx vitest run src/scanner/rules/gdpr-checks.test.ts
npx @attestlens/cli scan .
```

Expect `npx vitest run` to run 502+ tests. Before committing code changes,
`npx tsc --noEmit` and `npx vitest run` must both pass.

## Architecture

- `src/schema/` - Zod schemas and exported TypeScript types, including
  `ComplianceReport`, `Jurisdiction`, regulation principles, findings, opinions,
  rule packs, and reform schemas.
- `src/scanner/` - scanner orchestrator, adapters, URL scanning, MCP scanning,
  supply-chain/OSV checks, behavioral checks, IaC checks, gitleaks integration,
  reform scanning, and scanner types.
- `src/scanner/rules/` - embedded rule packs, AU checks, CCPA checks, GDPR
  checks, principle metadata, loader/cache logic, and rule tests.
- `src/mapping/` - mapping engine from scanner findings to regulation principles
  with citations, status, and confidence.
- `src/questionnaire/` - questionnaire engine, sessions, prompts, evaluator, SMB
  workflow, AU/CCPA/GDPR question banks, and attest flow.
- `src/opinion/` - deterministic opinion engine that produces verdicts,
  confidence, evidence chains, and assessment summaries.
- `src/report/` - report generation for JSON, HTML, Markdown, PDF, SMB, opinion,
  reform, and agent-facing formats.
- `src/mcp/` - MCP server with 8 tools, Zod input/output schemas,
  `structuredContent`, fail-closed path security, and sanitized errors.
- `src/cli/` - Commander.js CLI entry point and command wiring.
- `src/monitor/` - continuous monitoring implementation: webhook receiver,
  baselines, diff/regression detection, queueing, checkout, and reporting.
- `docs/` - product, roadmap, validation, and status documentation. Treat
  `docs/STATUS.md` as the current state source of truth.

Reform code currently lives in `src/scanner/reform.ts`, `src/schema/reform.ts`,
and report/MCP/CLI wiring. Do not create a parallel `src/reform/` tree unless
you are intentionally refactoring the module.

## Key Files

- `src/schema/index.ts` - central Zod schemas and core exported types.
- `src/mcp/index.ts` - MCP server, 8 tools, security boundary, schemas, and
  tool registration.
- `src/scanner/orchestrator.ts` - scanner orchestration and adapter execution.
- `src/mapping/engine.ts` - regulation mapping rules and mapping engine.
- `src/report/generator.ts` - compliance report generation.
- `src/scanner/rules/embedded.ts` - embedded AU/CCPA/GDPR rule-pack manifests.
- `src/scanner/rules/loader.ts` - rule-pack loading, jurisdiction availability,
  cache behavior, and remote update limits.
- `docs/STATUS.md` - current shipped state, tests, risks, and phase history.
- `docs/ROADMAP.md` - planned sequencing and positioning.

## Coding Conventions

- TypeScript strict mode is enabled. Do not introduce implicit `any` or unsafe
  null handling.
- Use Zod v3 (`import { z } from 'zod'`). Do not migrate to Zod v4.
- Use Vitest with `describe`, `it`, and `expect`.
- Keep the compliance engine deterministic. Same input must produce the same
  output.
- Use schema-first data boundaries. Add or update Zod schemas when changing MCP
  inputs/outputs, report shapes, scanner findings, or persisted structures.
- Prefer explicit jurisdiction parameters for multi-jurisdiction behavior. Keep
  AU-only defaults backward compatible when `--jurisdiction` is omitted.
- Scanner findings must map to regulation principles with citations. Do not emit
  unmapped compliance findings.
- Advisory or negative-detection rules should use `status: 'unknown'` and
  `confidence: 0.5` unless there is explicit legal basis for a stronger status.
- Redact special-category values in findings with `[REDACTED]`. Never store raw
  health, biometric, sexual-orientation, or similarly sensitive values.
- MCP tools should return Zod-validated `structuredContent`, not loose raw text.
- MCP validation errors should return `isError: true` tool responses. Do not use
  `McpError` for ordinary validation failures.
- Keep generated/package output out of source changes unless the task is
  explicitly about packaging or publishing.

## Hard Constraints

1. Never add LLM or AI calls to the compliance engine.
2. Never change a regulation principle mapping to `status: 'fail'` without
   explicit legal basis.
3. Never store raw special-category values in findings.
4. Always add tests for new scanner rules, mapping rules, questionnaire
   questions, MCP schemas, and report behavior.
5. Always add Zod schemas for new MCP tool inputs and outputs.
6. Always use the `jurisdiction` parameter for multi-jurisdiction features.
7. Always preserve AU-only defaults and backward compatibility.
8. Always keep MCP filesystem and URL scanning fail-closed.
9. Never claim global compliance coverage.

## Common Workflows

### Add A Scanner Rule

1. Add or update the rule in the relevant file under `src/scanner/rules/`.
2. Add principle mappings with citations. Use `unknown` for advisory or missing
   evidence findings unless a stronger legal status is justified.
3. Add focused tests next to the rule file.
4. Check downstream mapping/report expectations if the finding shape changes.
5. Run `npx tsc --noEmit` and the focused Vitest file, then run the full suite.

### Add A Mapping Rule

1. Update `src/mapping/engine.ts`.
2. Include jurisdiction, principle, obligation, citation, status, and confidence.
3. Add tests in `src/mapping/engine.test.ts`.
4. Verify report output if new principles or statuses should surface differently.

### Add A Questionnaire Question

1. Add the question to the correct bank in `src/questionnaire/`.
2. Keep jurisdiction and principle identifiers explicit.
3. Add evaluator/session tests for scoring and unknown-state behavior.
4. Verify CLI/MCP flows that consume questionnaire output.

### Add A New MCP Tool Or Change A Tool

1. Define Zod input and output schemas in `src/mcp/index.ts` or shared schema
   files.
2. Return `structuredContent` for successful responses.
3. Return `isError: true` for validation errors.
4. Preserve sanitized errors at the MCP boundary.
5. Add or update `src/mcp/index.test.ts`.
6. Set `openWorldHint: true` only for tools that access the network.

### Add A New Jurisdiction Pack

1. Add the principle enum/schema to `src/schema/index.ts`.
2. Create `src/scanner/rules/<jurisdiction>-principles.ts` with principle info
   and citations.
3. Create `src/scanner/rules/<jurisdiction>-checks.ts` with scanner rules.
4. Create `src/scanner/rules/<jurisdiction>-checks.test.ts`.
5. Create `src/questionnaire/<jurisdiction>-questions.ts`.
6. Add mapping rules to `src/mapping/engine.ts`.
7. Add the embedded pack to `src/scanner/rules/embedded.ts`.
8. Update `AVAILABLE_JURISDICTIONS` and `loadJurisdictionPacks` in
   `src/scanner/rules/loader.ts`.
9. Update jurisdiction flag handling in `src/cli/index.ts`.
10. Update MCP jurisdiction parameters in `src/mcp/index.ts`.
11. Update jurisdiction sections in `src/report/generator.ts`.
12. Run `npx tsc --noEmit` and `npx vitest run`.

## MCP Security Checklist

When modifying `src/mcp/index.ts` or scan entry points, preserve:

- Fail-closed filesystem access with default allowed roots of `[process.cwd()]`.
- Symlink escape blocking via `fs.realpath`.
- DNS rebinding protection through `ATTESTLENS_URL_SCAN_DNS_PIN`.
- TOCTOU revalidation before scans.
- Opaque resource URIs such as `attestlens://root/<id>`, not `file://` paths.
- Error sanitization with no raw paths or stack traces crossing the MCP boundary.
- AbortSignal cancellation support.
- `openWorldHint: true` for network tools: scan, scan_url, and audit.
- `openWorldHint: false` for local-only tools: map, opinion, check,
  compliance_check, and reform.

## Git Workflow

- Branch from `main` with `feature/<name>`.
- Conventional commit messages: `feat:`, `fix:`, `docs:`, `test:`, `chore:`.
- Squashed commits inside feature branches are fine.
- Merge feature branches with `git merge --no-ff feature/<name>`.
- Do not stage unrelated local changes.
