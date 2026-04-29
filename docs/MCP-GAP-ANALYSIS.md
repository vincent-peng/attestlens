# MCP Best Practices Gap Analysis — AttestLens

**Date:** 2026-04-29
**Spec version:** 2025-11-25 (latest)
**SDK version:** @modelcontextprotocol/sdk v1.29.0
**Server version:** 0.2.0

---

## Sources Researched

1. **MCP Specification 2025-11-25** — tools, resources, tasks, changelog
2. **MCP Blog: "Tool Annotations as Risk Vocabulary"** (2026-03-16) — annotation semantics, lethal trifecta, evaluation framework
3. **MCP Best Practices Guide** (mcp-best-practice.github.io) — enterprise patterns, security, tooling discipline
4. **AgentPatterns.ai: "MCP Server Design: A Server Author's Checklist"** — agent-friendly server patterns

---

## Overall Assessment: **B+ — Good foundation, several modern spec gaps**

AttestLens implements the core MCP tooling contract correctly: stdio transport, 8 well-named tools with `title` and `annotations`, proper `readOnlyHint`/`openWorldHint`, input validation, and path traversal protection. Where it falls short is adopting newer spec features (2025-06-18 and 2025-11-25) and following community best practices around structured outputs, error handling granularity, and capability declaration.

---

## ✅ What We Do Well

### 1. Tool Annotations — ✅ Compliant
- All 8 tools have `annotations` with `readOnlyHint` and `openWorldHint`
- `openWorldHint: true` correctly set on `attestlens_scan`, `attestlens_scan_url`, `attestlens_audit` (they support `externalEnrichment` → OSV.dev/npm)
- All other tools correctly set `openWorldHint: false`
- `readOnlyHint: true` on all tools — correct, our tools never modify the filesystem

### 2. Tool Titles — ✅ Compliant
- Every tool has a human-readable `title` per spec

### 3. Tool Naming — ✅ Compliant
- All tool names use `attestlens_` prefix + snake_case, within 128 chars, only valid characters

### 4. Input Validation — ✅ Strong
- Path validation with traversal protection (`[;|`$\\]` regex)
- `ATTESTLENS_ALLOWED_ROOTS` environment variable for path restriction
- URL protocol validation (http/https only)
- Scanner timeout validation (positive integer)
- Findings array validation for `attestlens_map`

### 5. Single Responsibility — ✅ Good
- One clear domain: Australian Privacy Act compliance
- Bounded toolset: 8 focused tools, no "kitchen sink"

### 6. Stdio Transport — ✅ Appropriate
- Correct choice for a local CLI/desk tool
- Uses `StdioServerTransport` properly
- Logs to stderr (compliant with 2025-11-25 clarification)

---

## ⚠️ Gaps to Address (Priority Order)

### GAP-1: Missing `destructiveHint` and `idempotentHint` — **Medium**

**Spec:** `ToolAnnotations` has 4 boolean hints: `readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`. Defaults: `destructiveHint: true`, `idempotentHint: false`.

**Our state:** We set `readOnlyHint` and `openWorldHint` but omit `destructiveHint` and `idempotentHint`.

**Impact:** Clients that don't know our tools are read-only will apply the pessimistic default `destructiveHint: true` — meaning they'll show confirmation prompts before every scan. Since all our tools are non-destructive, this creates unnecessary friction.

**Fix:** Add explicit `destructiveHint: false` and `idempotentHint: true` (all our tools are idempotent — same input → same output) to all 8 tool annotations.

**Effort:** ~10 lines changed.

---

### GAP-2: No `outputSchema` or `structuredContent` — **High**

**Spec (2025-06-18):** Tools MAY provide an `outputSchema` (JSON Schema) and return `structuredContent` alongside `content`. The spec says: *"For backwards compatibility, a tool that returns structured content SHOULD also return the serialized JSON in a TextContent block."*

**Our state:** All 8 tools return only `{ content: [{ type: 'text', text: JSON.stringify(...) }] }`. No `outputSchema`, no `structuredContent`.

**Impact:**
- Clients can't validate our output against a schema
- LLMs get raw JSON strings instead of structured, typed data — wastes tokens on parsing
- No programmatic consumption possible (agents must parse stringified JSON)
- This is the **biggest gap** vs. modern MCP standards

**Fix:** Define `outputSchema` for each tool (we already have structured return shapes). Return both `structuredContent` and `content` (TextContent with JSON string for backward compat). This is especially valuable for `attestlens_opinion`, `attestlens_check`, and `attestlens_compliance_check` which return well-defined schemas.

**Effort:** Medium — need to write 8 output schemas and refactor return shapes. ~200-300 lines.

---

### GAP-3: No `isError: true` for Tool Execution Errors — **Medium**

**Spec:** Tool execution errors (validation failures, business logic errors) should be returned with `isError: true` in the result, NOT as JSON-RPC protocol errors. This enables model self-correction.

**Our state:** We throw `McpError` (protocol-level errors) for input validation issues like "path does not exist" or "invalid URL". Per the 2025-11-25 changelog (SEP-1303): *"Clarify that input validation errors should be returned as Tool Execution Errors rather than Protocol Errors to enable model self-correction."*

**Impact:** LLMs can't self-correct — they get a protocol error and don't know what went wrong or how to fix it.

**Fix:** For user-correctable errors (path not found, URL invalid, unknown principle), return `{ content: [{ type: 'text', text: '...actionable error...' }], isError: true }` instead of throwing `McpError`. Reserve `McpError` for truly malformed requests (missing required params, wrong types).

**Effort:** ~30-40 lines changed across error handling.

---

### GAP-4: No `listChanged` capability — **Low**

**Spec:** Servers that support tools MUST declare the `tools` capability, and `listChanged` indicates whether the server will emit notifications when the tool list changes.

**Our state:** `{ capabilities: { tools: {} } }` — no `listChanged`.

**Impact:** Low — our tool list is static (doesn't change at runtime). But declaring `{ listChanged: false }` explicitly is more correct than omitting it.

**Fix:** Change to `{ capabilities: { tools: { listChanged: false } } }`.

**Effort:** 1 line.

---

### GAP-5: No `additionalProperties: false` on inputSchemas — **Low**

**Spec:** *"For tools with no parameters, use `{ type: 'object', additionalProperties: false }` — Recommended: explicitly accepts only empty objects."*

**Our state:** Some tools with optional-only params don't set `additionalProperties: false`. While not strictly required (only "recommended" for no-param tools), it's a best practice for strict validation.

**Impact:** Low — clients might pass unexpected extra properties that we silently ignore.

**Fix:** Add `additionalProperties: false` to all 8 `inputSchema` definitions.

**Effort:** 8 lines.

---

### GAP-6: No `execution.taskSupport` — **Low (experimental)**

**Spec (2025-11-25, experimental):** Tools can declare `execution: { taskSupport: 'optional' | 'required' | 'forbidden' }` for long-running operations that benefit from polling.

**Our state:** Not declared. Default is `'forbidden'`.

**Impact:** For `attestlens_audit` and `attestlens_scan` which can take 10-60+ seconds on large projects, task support would let clients poll for results instead of blocking. However, this spec is experimental. Worth noting for future but not blocking.

**Fix (deferred):** Once tasks spec stabilizes, add `execution: { taskSupport: 'optional' }` to `attestlens_scan`, `attestlens_audit`, `attestlens_reform`.

---

### GAP-7: No `resources` capability — **Low**

**Spec:** MCP servers can expose resources (readable data) and resource templates for context injection.

**Our state:** We don't expose any resources. All data access goes through tools.

**Impact:** Low currently. Resources would be useful if we wanted to expose things like:
- A resource template `attestlens://principles/{id}` for APP principle definitions
- A resource for the current scan report
- But tools work fine for our use case

**Fix (optional):** Consider adding a `resources/list` that exposes APP principle definitions as readable resources, so agents can fetch them for context without calling a tool.

---

### GAP-8: No `prompts` capability — **Low**

**Spec:** MCP servers can expose prompts — pre-defined templates that standardize interactions.

**Our state:** No prompts exposed.

**Impact:** Low. Could be useful for standardized compliance review prompts, but not critical.

**Fix (optional):** Consider adding prompts like "review-compliance" that combine opinion + check calls.

---

### GAP-9: No semantic versioning / deprecation policy — **Low**

**Best practice:** Tools should follow additive change, version schemas, and publish deprecations.

**Our state:** No version on tool schemas. If we rename a tool or change output shape, there's no migration path.

**Impact:** Low now, becomes high once we have external consumers. Before npm publish we should define this.

**Fix:** Add a `version` field to server metadata (already done: `ATTESTLENS_VERSION`). Document a deprecation policy for tool schemas.

---

### GAP-10: No rate limiting — **Low**

**Best practice:** Servers should rate-limit tool invocations.

**Our state:** No rate limiting. A client could spam `attestlens_scan` in a loop.

**Impact:** Low for local stdio server (only one client at a time). Becomes important for HTTP transport.

**Fix (optional):** Add a simple rate limiter (e.g., max 10 calls/minute per tool) if we ever add HTTP transport.

---

## 📋 Priority Action Plan

| Priority | Gap | Effort | Before npm publish? |
|----------|-----|--------|-------------------|
| **P0** | GAP-2: outputSchema + structuredContent | Medium | ✅ Yes |
| **P1** | GAP-1: destructiveHint + idempotentHint | Small | ✅ Yes |
| **P1** | GAP-3: isError for tool execution errors | Small | ✅ Yes |
| **P2** | GAP-4: listChanged: false | Trivial | ✅ Yes |
| **P2** | GAP-5: additionalProperties: false | Trivial | ✅ Yes |
| **P3** | GAP-9: Deprecation policy | Small | ⚠️ Document before publish |
| **Defer** | GAP-6: taskSupport (experimental) | Medium | ❌ Wait for spec stabilization |
| **Defer** | GAP-7: resources | Medium | ❌ Optional enhancement |
| **Defer** | GAP-8: prompts | Small | ❌ Optional enhancement |
| **Defer** | GAP-10: rate limiting | Small | ❌ Only needed for HTTP |

---

## Lethal Trifecta Assessment

The [MCP blog's lethal trifecta](https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations/) identifies three capabilities that, combined, enable data exfiltration: access to private data, exposure to untrusted content, ability to externally communicate.

**AttestLens risk profile:**
- ✅ **No exfiltration vector** — all tools are read-only, no write/communicate tools
- ⚠️ **Reads private data** — scans local filesystem (but bounded by `ATTESTLENS_ALLOWED_ROOTS`)
- ⚠️ **Sees untrusted content** — `attestlens_scan_url` fetches external URLs, `externalEnrichment` hits OSV.dev/npm
- ✅ **Cannot communicate externally** — no write/POST/SEND tools at all

**Verdict:** Safe. We have two legs of the trifecta but the third (exfiltration) is absent. The `readOnlyHint: true` + `destructiveHint: false` annotations (once GAP-1 is fixed) make this explicit to clients.

---

## Quick Build Checklist (from MCP Best Practices)

| Item | Status | Notes |
|------|--------|-------|
| ✅ Purpose and scope | Clear | Single domain: AU Privacy Act compliance |
| ✅ SDK and spec | Documented | SDK v1.29.0, spec 2025-11-25 |
| ⚠️ Security: OAuth scopes | N/A | Local stdio, no auth needed |
| ✅ Security: Least-privilege tools | Good | All read-only |
| ⚠️ Security: Approvals for high-risk | N/A | No high-risk tools |
| ✅ Validation: Strong input schemas | Good | Path/URL validation, required fields |
| ❌ Validation: Output schemas | Missing | GAP-2 |
| ✅ Operations: Health/readiness | N/A | Ephemeral stdio process |
| ⚠️ Observability: Structured audit logs | Partial | Logs to stderr, no structured format |
| ✅ Compatibility: Versioned schemas | Partial | Server version in metadata |
| ✅ Packaging | Good | npm package, bin entry |
| ✅ Docs | Good | README, CLI help, MCP tool descriptions |