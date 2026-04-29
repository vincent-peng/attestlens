# Phase 5A Code Review & Security Audit — Codex Findings

Review range: `926a67c..fb98378` on `main`

## SECURITY FINDINGS

### S-001 — P0: gitleaksPath Arbitrary Code Execution
- **Description**: MCP clients can choose `gitleaksPath`, and the scanner executes it via `execFile`. A relative path can execute a project-controlled binary from the scan target.
- **Impact**: Arbitrary code execution as the MCP server user, despite read-only tool annotations.
- **Fix**: Remove `gitleaksPath` from MCP input. Configure the binary server-side only, require a trusted absolute path, and reject client-controlled executable paths.
- **File**: `src/mcp/index.ts:141`, `src/scanner/gitleaks.ts:148`

### S-002 — P1: DNS Rebinding SSRF
- **Description**: URL SSRF protection resolves DNS before `fetch`, but `fetch` resolves the hostname again. DNS rebinding can pass the public-IP check and then connect to a private IP.
- **Impact**: A malicious scan URL could reach internal services.
- **Fix**: Pin vetted DNS results into the actual request using a custom dispatcher/lookup, or enforce an allowlist for URL scanning in MCP mode.
- **File**: `src/scanner/url-scan.ts:596`

### S-003 — P1: TOCTOU on validatePath
- **Description**: `validatePath()` blocks top-level symlink escapes, but it is still TOCTOU-prone. After validation returns a path string, scanners/external tools reopen that path later.
- **Impact**: A writable allowed root could be swapped to a symlink after validation and scanned outside the allowed root.
- **Fix**: Revalidate immediately before each adapter, use symlink-safe traversal, and sandbox/disable external scanners for untrusted MCP clients.
- **File**: `src/mcp/index.ts:418`, `src/scanner/orchestrator.ts:159`

### S-004 — P2: Resource Path Disclosure
- **Description**: `resources/list` exposes canonical allowed-root paths as `file://` URIs. `resources/read` also echoes unknown requested URIs in errors.
- **Impact**: Local username, checkout layout, and workspace paths leak to MCP clients.
- **Fix**: Use opaque `attestlens://root/<id>` resource URIs and return generic "Resource not found" errors.
- **File**: `src/mcp/index.ts:397`, `src/mcp/index.ts:1111`

### S-005 — P2: Error Messages Leak Internals
- **Description**: Successful scan `errors` are passed through directly. Adapter messages can include raw command errors, absolute paths, or implementation details.
- **Impact**: Internal paths and command details can leak inside successful `structuredContent`.
- **Fix**: Sanitize scanner errors at the MCP boundary; expose `source`, `code`, `recoverable`, and a generic safe message only.
- **File**: `src/mcp/index.ts:642`

## CODE QUALITY FINDINGS

### Q-001 — P2: normalizeStructuredContent() JSON round-trip
- **Description**: Drops `undefined`, coerces `Date`, throws on `BigInt` or circular refs.
- **Fix**: Replace with explicit JSON-safe normalizer or fail with controlled tool error.
- **File**: `src/mcp/index.ts:369`

### Q-002 — P2: Zod schemas don't fully encode handler constraints
- **Description**: `scannerTimeoutMs` accepts any number in schema but handler requires positive integer. `gitleaksPath` accepts any string.
- **Fix**: Use `z.number().int().positive().max(...)` and remove/scope dangerous fields like `gitleaksPath`.
- **File**: `src/mcp/index.ts:132`

### Q-003 — P3: `catch (error: any)` in cancellation/error paths
- **Fix**: Use `unknown`, normalize with `error instanceof Error`, classify abort errors consistently.
- **File**: `src/scanner/orchestrator.ts:186`

## TEST COVERAGE GAPS

### T-001: Contract tests call handleToolCall() directly, not actual MCP tools/call
### T-002: Error contracts not covered for all 8 tools
### T-003: No AbortSignal tests
### T-004: Resource negative paths are thin
### T-005: No DNS rebinding or TOCTOU tests

## MCP SPEC COMPLIANCE

### M-001: resources/read not-found uses InvalidParams (-32602) instead of -32002
### M-002: Audit text content doesn't mirror structuredContent JSON (SHOULD, not MUST)

## VERDICT

**FAIL for untrusted MCP clients.** The `gitleaksPath` execution surface is the blocker. For trusted local-only use, the Phase 5A structured response work is mostly sound, but DNS rebinding, TOCTOU hardening, resource path disclosure, and cancellation tests should still be fixed.