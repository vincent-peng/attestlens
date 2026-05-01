# Phase 10.5 Code Review + Security Audit

**Reviewer:** Ada (in-depth review)
**Date:** 2026-05-01
**Scope:** All Phase 10.5 changes (SARIF formatter, exit-threshold, CLI installer, MCP subcommand, package metadata, MCP path validation fix)

---

## Summary

538 tests passing, tsc clean, npm pack passes. The implementation is solid overall — clean separation of concerns, proper backup/idempotency in the installer, correct SARIF v2.1.0 structure. But there are real issues to fix before merge.

---

## 🔴 P0 — Must Fix Before Merge

### S-001: Cline dotted key creates incorrect JSON structure

**File:** `src/cli/install.ts` line ~48, `serverKey: 'cline.mcpServers'`

The Cline client uses `serverKey: 'cline.mcpServers'` which treats the dotted string as a **single top-level key** rather than nested access. The `ensureServerContainer` and `getServerContainer` functions do `config[serverKey]` — this creates a top-level key literally named `"cline.mcpServers"` instead of `{ "cline": { "mcpServers": { ... } } }`.

VS Code settings.json uses dotted keys like `cline.mcpServers` as flat keys in the JSON, so **this may actually be correct for VS Code settings**. However, the `removeServerConfig` cleanup logic at line ~152 does:
```ts
delete (nextConfig as Record<string, unknown>)[definition.serverKey];
```
This deletes the entire `"cline.mcpServers"` container — which would remove **all** Cline MCP servers, not just Clearway's. If `cline.mcpServers` is a flat key in VS Code settings containing `{ clearway: {...}, otherServer: {...} }`, deleting the whole key is wrong.

**Fix:** When uninstalling, only delete the `clearway` key inside the container — never delete the container itself. The existing code at line ~148-150 does `delete container[CLEARWAY_SERVER_NAME]` correctly, but then checks `if (Object.keys(container).length === 0)` and deletes the parent. For dotted keys in VS Code settings, this is destructive. Remove the empty-container cleanup for dotted keys, or only do it for non-dotted keys.

**Severity:** High — data loss on uninstall.

### S-002: SARIF formatter crashes on findings without matching jurisdiction mapping

**File:** `src/formatters/sarif.ts` line ~258-262, `getPrimaryMapping()`

```ts
function getPrimaryMapping(finding: AttestLensFinding, jurisdiction: Jurisdiction): RegulationMapping {
  const mapping = finding.regulationMappings.find((candidate) => candidate.jurisdiction === jurisdiction);
  if (!mapping) {
    throw new Error(`Finding ${finding.id} is missing a ${jurisdiction} regulation mapping`);
  }
  return mapping;
}
```

This throws an unhandled error if a finding has no mapping for the requested jurisdiction. This can happen legitimately:
- Scan with `--jurisdiction us-ccpa` but the project only triggers AU rules
- URL scan findings that only have `au-privacy-act` mappings

The `regulationMappings` field is required on findings, but there's no guarantee every finding has a mapping for every jurisdiction. The scan command correctly filters by jurisdiction in the orchestrator, but `formatSarif` receives all findings and then tries to find a mapping per-jurisdiction.

**Fix:** Either (a) filter findings to only those with a matching regulationMapping before passing to `formatSarif`, or (b) make `getPrimaryMapping` return a fallback/synthetic mapping instead of throwing. Option (a) is cleaner — the SARIF output should only contain findings relevant to the requested jurisdiction.

**Severity:** High — runtime crash on valid input.

### S-003: Stale hardcoded version in report generator

**File:** `src/report/generator.ts` line 45

```ts
const ATTESTLENS_VERSION = '0.2.0';
```

This was the bug we fixed in Phase 1 (CLI now reads from package.json), but the report generator still has a hardcoded `0.2.0`. All HTML, Markdown, and PDF reports show "AttestLens v0.2.0" — which is wrong. The actual version is 0.4.0.

This isn't a Phase 10.5 regression (it was already there), but it's a bug that should be fixed now since we're touching the format system.

**Fix:** Replace the hardcoded constant with `readCliPackageVersion()` or pass version through `ReportOptions`.

**Severity:** High — user-facing incorrect version in all generated reports.

---

## 🟡 P1 — Should Fix Before Merge

### S-004: `emitSarifOutput` allows arbitrary file write via `--sarif-output`

**File:** `src/cli/index.ts` line ~1626-1633

```ts
async function emitSarifOutput(payload: unknown, outputPath?: string): Promise<void> {
  const resolvedOutputPath = path.resolve(outputPath);
  await fs.mkdir(path.dirname(resolvedOutputPath), { recursive: true });
  await fs.writeFile(resolvedOutputPath, content, 'utf-8');
}
```

The `--sarif-output` flag accepts any path, resolves it, and writes. In CI contexts, this is generally fine (the GitHub Action controls the path). But in local CLI usage, a user could accidentally or maliciously pass `/etc/passwd` or `~/.ssh/authorized_keys` as the output path.

**Fix:** Validate that the output path doesn't write outside the current working directory or a designated output directory. At minimum, refuse to write to paths containing `..` after resolution, and refuse paths under `/etc`, `~/.ssh`, etc. Or simply: only allow relative paths (resolve against CWD), reject absolute paths.

**Severity:** Medium — unlikely in practice, but the CLI is a supply-chain tool; defense in depth matters.

### S-005: Exit code 2 for `CommanderError` may suppress legitimate errors

**File:** `src/cli/index.ts` line ~2038-2043

```ts
try {
  await program.parseAsync();
} catch (error: any) {
  if (error instanceof CommanderError) {
    const exitCode = error.exitCode === 0 ? 0 : 2;
    process.exit(exitCode);
  }
  process.exit(2);
}
```

Commander uses exit code 1 for "help displayed" and "version displayed" by default. The new code maps all non-zero CommanderError exit codes to 2. But `commander.helpDisplayed` has exit code 0, so that's fine. The concern: if Commander throws for an unknown option, the exit code is 1 (Commander's default), which gets remapped to 2. This is actually correct for our convention (2 = tool error), but it changes behavior — previously, unknown options would exit 1, now they exit 2.

This is fine semantically but should be documented as a behavior change.

**Severity:** Low — correct semantics, just note it.

### S-006: Inconsistent exit codes across commands

**File:** `src/cli/index.ts` — multiple locations

Several commands still use `process.exit(1)` for errors:
- `attest` command (line ~407): `process.exit(1)` on error
- `compliance-check` (line ~506): `process.exit(1)` on error  
- `reform` (line ~574): `process.exit(1)` on error
- `report` (line ~618): `process.exit(1)` on error
- `update-rules` (line ~647): `process.exit(1)` on error

The Phase 10.5 convention is: exit 1 = findings exceed threshold, exit 2 = tool error. These commands use exit 1 for errors, which is the old convention. This is inconsistent.

**Fix:** Change all error exits to `process.exit(2)` to match the new convention. Only `scan` and `audit` should exit 1 for threshold-exceeding findings.

**Severity:** Medium — confusing for CI pipelines that distinguish between "findings" and "tool errors".

### S-007: SARIF `basePath` uses `fs.realpath` but `relativizeFindingPath` also calls `fs.realpath` on each file

**File:** `src/formatters/sarif.ts` lines ~67-68, ~97

The `formatSarif` function calls `fs.realpath` on the base path once, then `relativizeFindingPath` calls `fs.realpath` on every individual finding file path. For large scans with hundreds of findings, this is N+1 filesystem calls. If a finding file doesn't exist (e.g., it was deleted during scan), `realpath` falls back to `path.resolve`.

**Fix:** Cache realpath results, or do realpath resolution once upfront. The current fallback is correct, just inefficient.

**Severity:** Low — performance, not correctness.

---

## 🟢 P2 — Nice to Have

### S-008: `removeServerConfig` empty-container cleanup is aggressive

When uninstalling removes the last server from a container, the code deletes the entire container key. For `claude-desktop`'s `mcpServers`, this would remove the entire `mcpServers` key, which could break other MCP servers if the user has them. Only delete the container if it's truly empty AND the key is not a well-known shared key like `mcpServers`.

### S-009: `server.json` doesn't include `annotations` field

The MCP tools have `annotations` (readOnlyHint, openWorldHint) in the actual server but `server.json` omits them. The MCP Registry spec supports per-tool annotations. Adding them would give clients better information.

### S-010: SARIF output doesn't include `invocations` block

The SARIF spec supports a `run.invocations` array that records how the tool was invoked (command line, start time, end time, exit code). This is valuable for audit trails in CI. Not required, but recommended for production-grade SARIF.

### S-011: `attestlens mcp` subcommand doesn't pass through CLI args

The MCP subcommand just calls `await main()` without forwarding any arguments. If someone runs `attestlens mcp --port 8080`, the flag would be ignored. Fine for now (stdio only), but worth noting for future HTTP transport support.

---

## ✅ What's Done Well

1. **SARIF structure** — Correct v2.1.0 schema, proper `$schema` URI, jurisdiction-qualified rule IDs, deterministic fingerprints
2. **Exit code separation** — 0/1/2 distinction is clean and follows industry convention
3. **Installer idempotency** — Second install is a no-op (checks serialized config equality)
4. **Installer backup** — Creates `.bak-<timestamp>` before modifying
5. **Dry-run support** — `--dry-run` on install/uninstall doesn't write files
6. **Relative path enforcement** — SARIF uses relative paths, falls back to basename for absolute paths outside base
7. **MCP path validation fix** — macOS `/var` vs `/private/var` symlink edge case properly handled by checking both resolved and canonical roots
8. **`program.exitOverride()`** — Prevents Commander from calling `process.exit` internally, giving us control over exit codes
9. **No secrets in SARIF** — Finding descriptions and messages are included, but no tokens/keys
10. **Test coverage** — 15 new tests, including edge cases (empty findings, no file path, invalid severity, idempotent install)

---

## Required Actions Before Merge

| ID | Severity | What | Effort |
|----|----------|------|--------|
| S-001 | P0 | Fix Cline uninstall — don't delete entire dotted-key container | Small |
| S-002 | P0 | Fix SARIF crash on missing jurisdiction mapping | Small |
| S-003 | P0 | Fix hardcoded `0.2.0` in report generator | Small |
| S-004 | P1 | Validate `--sarif-output` path (reject writes outside CWD/output dir) | Small |
| S-006 | P1 | Unify error exit codes to 2 across all commands | Small |
| S-005 | P2 | Document CommanderError exit code behavior change | Trivial |
| S-007 | P2 | Cache realpath results in SARIF formatter | Trivial |
| S-008 | P2 | Don't delete `mcpServers` container on last-server removal | Small |
| S-009 | P2 | Add annotations to server.json | Trivial |

**Verdict:** 3 must-fix issues (P0), 2 should-fix (P1). Total fix effort: ~1 hour. The P0s are real bugs that will cause data loss (S-001), crashes (S-002), and incorrect output (S-003).