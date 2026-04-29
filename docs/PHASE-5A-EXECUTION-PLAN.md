# Phase 5A: MCP Contract Hardening — Execution Plan

**Branch:** `feature/mcp-hardening` from main (commit 926a67c)
**Goal:** Production-grade MCP server ready for npm publish

## Step 1: Fail-Closed Filesystem + Security (P0)

### 1a: Default allowed roots to `process.cwd()`
- When `ATTESTLENS_ALLOWED_ROOTS` is unset, default to `[process.cwd()]` instead of allowing any directory
- Use `path.delimiter` instead of `:` for cross-platform compatibility
- Resolve both target and roots through `fs.realpath` to block symlink escapes

### 1b: Add `ToolInputError` class
- Separate user-correctable input errors from protocol errors
- `ToolInputError` → `isError: true` result (not `McpError` throw)
- Keep `McpError` for truly malformed requests only

### 1c: Convert validation errors to `isError: true`
- Path validation: "path does not exist", "path is not a directory", "path is outside allowed roots"
- URL validation: "invalid URL", "unsupported protocol"
- Principle validation: "APP principle not found"
- Format validation: "unsupported report format"
- All of these should return `{ content: [{ type: 'text', text: '...' }], isError: true }`

## Step 2: Structured Content + Output Schemas (P0)

### 2a: Define output schemas for stable JSON tools
- `attestlens_check` → structured result schema
- `attestlens_compliance_check` → structured result schema
- `attestlens_map` → structured result schema
- These three have stable, well-defined return shapes

### 2b: Create `AuditOutput` envelope for `attestlens_audit`
- Wrap polymorphic output (JSON/HTML/Markdown/PDF/agent) in a structured envelope
- `structuredContent` contains the parsed JSON result
- `content` still contains the stringified version for backward compatibility

### 2c: Add `structuredContent` to tool results
- Every tool returns both `content` (text) and `structuredContent` (typed JSON)
- Per spec: "For backwards compatibility, a tool that returns structured content SHOULD also return the serialized JSON in a TextContent block"

## Step 3: McpServer Migration (P1)

### 3a: Replace low-level `Server` with `McpServer`
- Import from `@modelcontextprotocol/sdk/server/mcp.js`
- Use `server.registerTool()` with Zod input/output schemas
- Get automatic schema validation, annotations, and `listChanged` for free

### 3b: Add all 4 annotation hints
- `destructiveHint: false` on all tools (we never modify anything)
- `idempotentHint: true` on all tools (no environmental side effects)
- `readOnlyHint: true` on all tools (already done)
- `openWorldHint: true/false` per tool (already done)

### 3c: Bump SDK floor
- `@modelcontextprotocol/sdk: ^1.29.0`
- `zod: ^3.25.76` (for Zod v4 support in McpServer)

## Step 4: MCP Contract Tests (P1)

- Test annotations: all 4 hints present, correct values per tool
- Test `isError: true` on validation/business errors
- Test `structuredContent` present alongside `content` text
- Test fail-closed filesystem: no env → cwd only, outside roots → rejected
- Test symlink escape blocking
- Test `path.delimiter` splitting

## Step 5: APP/NDB Resources (P2)

- Expose APP principle definitions as MCP resources
- `attestlens://principles/{id}` → principle metadata
- `attestlens://principles` → list of all principles
- Read-only, no tool calls needed for reference data

## Step 6: Cancellation + Progress (P2)

- Thread `extra.signal` from MCP request handler into `ScannerOrchestrator.scan()`
- Emit MCP progress notifications for long scans
- Handle client cancellation gracefully (AbortSignal)

## Execution Order

1. Step 1 (security hardening) — must go first, affects everything else
2. Step 2 (structured content) — next biggest impact
3. Step 3 (McpServer migration) — architectural change, do after schemas
4. Step 4 (contract tests) — validate all the above
5. Step 5 + 6 (resources + cancellation) — can run in parallel after tests pass

## Codex Review Gate

After each step, run Codex code review + security audit before merging.