# MCP Cross-Examination - AttestLens

Date: 2026-04-29
Protocol revision checked: MCP 2025-11-25
Local SDK installed: `@modelcontextprotocol/sdk` 1.29.0 in `package-lock.json`
Package range declared: `@modelcontextprotocol/sdk` `^1.12.0` in `package.json`

## Scope And Sources

Local files reviewed:

- `src/mcp/index.ts`
- `src/mcp/index.test.ts`
- `docs/MCP-GAP-ANALYSIS.md`
- `package.json`
- `package-lock.json`
- `node_modules/@modelcontextprotocol/sdk/dist/esm/...` for installed SDK API verification
- `src/scanner/url-scan.ts` and `src/utils/target.ts` for URL/path security checks

Spec and best-practice sources:

- MCP 2025-11-25 Tools: https://modelcontextprotocol.io/specification/2025-11-25/server/tools
- MCP 2025-11-25 Schema Reference: https://modelcontextprotocol.io/specification/2025-11-25/schema
- MCP 2025-11-25 Key Changes: https://modelcontextprotocol.io/specification/2025-11-25/changelog
- MCP 2025-11-25 Tasks: https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/tasks
- MCP 2025-11-25 Roots: https://modelcontextprotocol.io/specification/2025-11-25/client/roots
- MCP 2025-11-25 Resources: https://modelcontextprotocol.io/specification/2025-11-25/server/resources
- MCP 2025-11-25 Prompts: https://modelcontextprotocol.io/specification/2025-11-25/server/prompts
- MCP 2025-11-25 Elicitation: https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation
- MCP 2025-11-25 Transports: https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
- MCP Security Best Practices: https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices
- SEP-1303: https://modelcontextprotocol.io/seps/1303-input-validation-errors-as-tool-execution-errors
- MCP blog, tool annotations: https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations/
- Community best-practice guide: https://mcp-best-practice.github.io/mcp-best-practice/best-practice/
- AgentPatterns tool engineering index: https://agentpatterns.ai/tool-engineering/

## Executive Verdict

`docs/MCP-GAP-ANALYSIS.md` is directionally correct, but too generous in three places:

1. It treats the MCP server as production-ready because the basic low-level protocol handlers work. The installed SDK now marks low-level `Server` as deprecated for normal server construction and provides `McpServer.registerTool`, `registerResource`, `registerPrompt`, output validation, and experimental task tooling that AttestLens is not using.
2. It treats path protection as strong, but `ATTESTLENS_ALLOWED_ROOTS` is optional and path checks use `path.resolve` instead of `fs.realpath`, so the default local MCP posture still allows any readable local directory and can be confused by symlink escapes inside an allowed root.
3. It says all tools should get output schemas, but `attestlens_audit` has polymorphic string/PDF/HTML/JSON behavior and needs a stable output envelope or split tools before an `outputSchema` can be honest.

The strongest production-grade sequence is:

1. Add structured tool results and output schemas for stable JSON tools.
2. Convert self-correctable tool failures to `isError: true`.
3. Move from low-level `Server` to high-level `McpServer` for tools, resources, prompts, schema conversion, and SDK-aligned error behavior.
4. Tighten filesystem boundary defaults and symlink handling before npm launch.
5. Add APP/NDB resources and a small prompt surface after the core tool contract is stable.

## Cross-Examination Of Existing 10 Gaps

| Existing gap | Verdict | Corrected assessment |
|---|---|---|
| GAP-1: Missing `destructiveHint` and `idempotentHint` | Correct, but partly overstated | The server only sets `readOnlyHint` and `openWorldHint` in `LOCAL_READ_ONLY_ANNOTATIONS` and `URL_READ_ONLY_ANNOTATIONS` (`src/mcp/index.ts:43-51`). MCP has four boolean hints plus `title` in annotations. Add all four for clarity. However, `idempotentHint` is about repeated calls having no additional environmental effect, not deterministic output. Scans include timestamps, durations, live URL state, and optional registry/OSV results, so the old claim "same input -> same output" is wrong. For read-only tools, idempotence is mostly implied by no side effects. |
| GAP-2: No `outputSchema` or `structuredContent` | Correct and understated | This is the most important MCP contract gap. All tool returns are JSON strings in `content` only (`src/mcp/index.ts:530-868`). The spec says structured results go in `structuredContent`, and if a tool declares `outputSchema`, the structured result must conform. The gap is bigger than 200-300 lines because `attestlens_audit` currently returns five different shapes depending on `format`. |
| GAP-3: No `isError: true` for tool execution errors | Correct and high priority | Current validation helpers throw `McpError(ErrorCode.InvalidParams)` for path, URL, timeout, principle, format, and findings errors (`src/mcp/index.ts:268-479`, `src/mcp/index.ts:606-609`, `src/mcp/index.ts:712-721`). SEP-1303 and the Tools spec now clearly put input validation and business logic failures in tool results with `isError: true`. Keep protocol errors for malformed RPC, unsupported methods, and server defects. |
| GAP-4: No `listChanged` capability | Correct but low value | Current capabilities are `{ tools: {} }` (`src/mcp/index.ts:877-881`). Since the tool list is static, `{ tools: { listChanged: false } }` is clearer. This is not a meaningful production risk. If migrating to `McpServer`, note the SDK auto-registers `tools.listChanged: true`; that is valid if the server can emit notifications, but static servers can still prefer false through low-level setup. |
| GAP-5: No `additionalProperties: false` | Overstated as a spec gap | The spec specifically recommends `additionalProperties: false` for no-parameter tools. AttestLens has no no-parameter tools. Adding it to parameterized schemas is still a good strictness practice, but it is not enough by itself because the current handler does manual reads from `args` and ignores extra fields anyway. Use Zod/SDK validation or explicit schema validation, then decide whether extra params are errors. |
| GAP-6: No `execution.taskSupport` | Correct to defer | Tasks are experimental in 2025-11-25. Do not add `execution: { taskSupport: "optional" }` until the server actually implements task-augmented calls. SDK 1.29 provides `server.experimental.tasks.registerToolTask`, but current `handleToolCall` is synchronous blocking from the client perspective. |
| GAP-7: No `resources` capability | Understated | APP/NDB principle definitions are stable, read-only, and useful as model context. They fit MCP resources better than tools. This should be P2 after structured results, not merely "maybe someday". Do not expose current scan reports as resources until the server has a durable report store and permission model. |
| GAP-8: No `prompts` capability | Correct, slightly understated | Compliance review prompt templates would add value because prompts are user-controlled templates. A small prompt set can standardize review workflows without adding new execution risk. Keep it P3, behind core tools/resources. |
| GAP-9: No semantic versioning/deprecation policy | Correct but fix is incomplete | Server metadata version already exists (`ATTESTLENS_VERSION = "0.2.0"`). The missing part is output contract versioning, schema compatibility tests, and a documented additive/deprecation policy. Add `schemaVersion` inside structured outputs and golden contract tests. |
| GAP-10: No rate limiting | Correct, transport-dependent | Low risk for local stdio. Required once Streamable HTTP is added, especially because URL scans perform external fetches and infra probes. The Tools spec security section expects servers to rate-limit tool invocations. |

## Missed Gaps

### NEW-1: Low-level `Server` is the wrong default API for this stage

Current code:

```ts
import { Server } from '@modelcontextprotocol/sdk/server/index.js';

export function createServer(): Server {
  const server = new Server(
    { name: 'attestlens', version: ATTESTLENS_VERSION },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [...MCP_TOOLS] }));
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    return handleToolCall(name, args as Record<string, unknown> | undefined);
  });

  return server;
}
```

Installed SDK 1.29 marks low-level `Server` as deprecated for normal use and says to use `McpServer` unless advanced custom handlers are required. `McpServer` provides:

- `registerTool` with `inputSchema`, `outputSchema`, annotations, and SDK output validation
- `registerResource` and `ResourceTemplate`
- `registerPrompt`
- `server.elicitInput`
- `experimental.tasks.registerToolTask`
- automatic tool validation behavior aligned with modern `isError` expectations

Recommendation:

```ts
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod/v4';

const server = new McpServer({
  name: 'attestlens',
  title: 'AttestLens',
  version: ATTESTLENS_VERSION,
  description: 'Australian Privacy Act APP/NDB compliance scanner.',
});

server.registerTool('attestlens_check', {
  title: 'Single Principle Compliance Check',
  description: 'Check one APP/NDB principle for a project.',
  inputSchema: {
    path: z.string().describe('Project directory to scan'),
    principle: z.enum(Object.keys(APPInfo) as [APPPrinciple, ...APPPrinciple[]]),
    strict: z.boolean().default(false),
  },
  outputSchema: attestlensCheckOutputSchema,
  annotations: LOCAL_READ_ONLY_ANNOTATIONS,
}, async (args, extra) => {
  const payload = await runPrincipleCheck(args, extra.signal);
  return jsonToolResult(payload);
});

await server.connect(new StdioServerTransport());
```

If you keep low-level `Server`, explicitly implement the same validation, structured output, progress/cancellation, resources, prompts, and error mapping yourself.

### NEW-2: `package.json` does not declare the SDK version actually being relied on

Current `package.json`:

```json
"@modelcontextprotocol/sdk": "^1.12.0",
"zod": "^3.24.0"
```

Current lockfile resolves:

```text
@modelcontextprotocol/sdk 1.29.0
zod 3.25.76
```

SDK 1.29 is the version verified here for output schemas, all annotation hints, Streamable HTTP, URL elicitation, and experimental tasks. The package manifest should make that minimum explicit.

Recommendation:

```json
"@modelcontextprotocol/sdk": "^1.29.0",
"zod": "^3.25.76"
```

Use `zod/v4` imports where adopting `McpServer.registerTool` examples, since SDK 1.29 documents that path while retaining compatibility with Zod 3.25+.

### NEW-3: Filesystem boundary should fail closed by default

Current behavior:

```ts
function getAllowedRoots(): string[] | undefined {
  if (!process.env.ATTESTLENS_ALLOWED_ROOTS) {
    return undefined;
  }
  return process.env.ATTESTLENS_ALLOWED_ROOTS.split(':').filter(Boolean);
}
```

If `ATTESTLENS_ALLOWED_ROOTS` is unset, any readable local directory can be scanned. For a local stdio MCP server, that is still a meaningful privacy boundary because clients and models can request arbitrary paths.

Recommendation:

```ts
async function getAllowedRoots(): Promise<string[]> {
  const configured = process.env.ATTESTLENS_ALLOWED_ROOTS
    ?.split(path.delimiter)
    .map((root) => root.trim())
    .filter(Boolean);

  const roots = configured && configured.length > 0 ? configured : [process.cwd()];
  return Promise.all(roots.map(async (root) => fs.realpath(path.resolve(root))));
}

export async function validatePath(targetPath: string): Promise<string> {
  if (!targetPath || typeof targetPath !== 'string') {
    throw new ToolInputError('path is required');
  }

  const resolved = path.resolve(targetPath);
  const realTarget = await fs.realpath(resolved).catch(() => {
    throw new ToolInputError(`path does not exist: ${resolved}`);
  });

  const allowedRoots = await getAllowedRoots();
  const isAllowed = allowedRoots.some((root) => (
    realTarget === root || realTarget.startsWith(root + path.sep)
  ));
  if (!isAllowed) {
    throw new ToolInputError('path is outside the allowed workspace roots');
  }

  const stat = await fs.stat(realTarget);
  if (!stat.isDirectory()) {
    throw new ToolInputError(`path is not a directory: ${resolved}`);
  }
  return realTarget;
}
```

Also consider MCP Roots. The 2025-11-25 Roots spec lets clients expose workspace roots; servers should respect those boundaries when available. For stdio editors, client roots plus `ATTESTLENS_ALLOWED_ROOTS` gives a cleaner consent story than a global filesystem default.

### NEW-4: Symlink escapes are not blocked

`path.resolve` prevents simple `..` traversal, but not symlink traversal. Example: allowed root `/repo`, symlink `/repo/outside -> /Users/alice`, request `/repo/outside/private`. Current code sees a path under `/repo`; the scanner follows the symlink.

Use `fs.realpath` for both target and roots before comparing.

### NEW-5: `ATTESTLENS_ALLOWED_ROOTS` uses `:` instead of `path.delimiter`

This is fine on macOS/Linux but breaks Windows drive-letter paths. Since this is an npm package, use `path.delimiter`.

### NEW-6: MCP cancellation/progress is not wired into scans

The SDK provides `extra.signal` to request handlers. The scanner adapter types already support `signal?: AbortSignal`, and the orchestrator has progress events, but `handleToolCall` ignores the request handler `extra` object and `ScannerOrchestrator.scan` does not accept an outer abort signal.

Recommendation:

- Thread `extra.signal` into orchestrator scan options.
- Emit MCP progress notifications for long scans before adopting tasks.
- Treat client cancellation as cancellation, not a late successful result.

### NEW-7: `attestlens_audit` needs a stable MCP output envelope

Current `attestlens_audit` returns:

- JSON string for `format: "json"`
- HTML string for `format: "html"`
- Markdown string for `format: "markdown"`
- Base64 JSON string for `format: "pdf"`
- agent JSON string for `format: "agent"`

A static `outputSchema` can represent this only with a broad wrapper or `oneOf`. The better MCP shape is an envelope:

```ts
type AuditOutput = {
  schemaVersion: 'attestlens.audit.v1';
  format: 'json' | 'agent' | 'html' | 'markdown' | 'pdf';
  report?: ComplianceReport | AgentReport;
  text?: string;
  artifact?: {
    filename: string;
    mimeType: string;
    encoding: 'base64';
    content: string;
  };
};
```

Then return the envelope in `structuredContent` and keep serialized JSON in `content[0].text`.

### NEW-8: Test coverage currently verifies text JSON, not MCP contracts

`src/mcp/index.test.ts` parses `response.content[0].text` for structured checks. Add contract tests that assert:

- every tool has all four boolean annotation hints
- stable JSON tools declare `outputSchema`
- successful JSON tools return matching `structuredContent`
- validation errors return `isError: true`
- unknown tools remain protocol errors
- `ATTESTLENS_ALLOWED_ROOTS` fail-closed and symlink behavior
- package dependency floor is `@modelcontextprotocol/sdk >= 1.29`

### NEW-9: Output sanitization is incomplete as a formal policy

Current output sanitization is good in places:

- target paths are reduced to basenames in MCP scan results
- URL credentials/query/hash are stripped from target URL output
- rule freshness cache paths are stripped by schema parsing/tests
- URL scanner has body-size limits and SSRF checks

But the Tools spec security section also expects sanitized outputs generally. Formalize what can be emitted in MCP payloads:

- no absolute local paths unless explicitly requested and allowed
- no raw scanner output containing secrets
- no unbounded HTML/JS snippets from URL scans
- no credentials in URLs
- stable redaction for environment-like values

## Lethal Trifecta Assessment

The prior assessment is mostly accurate but too absolute.

AttestLens alone:

- Reads private local data through path scans.
- Reads untrusted external data through `attestlens_scan_url` and optional OSV/npm enrichment.
- Does not provide an explicit send/email/upload/write tool.

So this server alone does not complete the classic trifecta. However, in a real MCP client session, AttestLens is likely composed with shell, browser, GitHub, Slack, email, or file-write tools. In that composed session:

- `attestlens_scan` can expose private code/security findings to the model.
- `attestlens_scan_url` can taint the model with attacker-controlled web content.
- another server/tool can provide egress.

Verdict: AttestLens does not itself provide the egress leg, but it can provide the private-data and untrusted-content legs. Marking `openWorldHint` accurately, failing closed on filesystem roots, minimizing raw outputs, and avoiding prompt-injection-prone report text in `structuredContent` all matter.

The gap analysis also says "`attestlens_scan`, `attestlens_scan_url`, and `attestlens_audit` are open-world." That is conservative and acceptable. `attestlens_scan` and `attestlens_audit` are only open-world when external enrichment is enabled, but annotations are static; keeping `openWorldHint: true` avoids understating the tool's possible behavior.

## MCP 2025-11-25 Feature Assessment

### Structured Content And `outputSchema`

Use this now.

Priority order:

1. `attestlens_check`
2. `attestlens_compliance_check`
3. `attestlens_map`
4. `attestlens_scan`
5. `attestlens_scan_url`
6. `attestlens_opinion`
7. `attestlens_reform`
8. `attestlens_audit` after output envelope refactor

Current:

```ts
return {
  content: [{
    type: 'text',
    text: JSON.stringify(payload, null, 2),
  }],
};
```

Should become:

```ts
function jsonToolResult<T extends Record<string, unknown>>(payload: T): ToolResponse {
  return {
    content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }],
    structuredContent: payload,
  };
}
```

Then every output schema must match exactly. If a result has `outputSchema`, SDK clients can validate `structuredContent`.

### Tool Annotations

Current:

```ts
const LOCAL_READ_ONLY_ANNOTATIONS = {
  readOnlyHint: true,
  openWorldHint: false,
} as const;

const URL_READ_ONLY_ANNOTATIONS = {
  readOnlyHint: true,
  openWorldHint: true,
} as const;
```

Should become:

```ts
const LOCAL_READ_ONLY_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

const OPEN_WORLD_READ_ONLY_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;
```

Do not describe idempotence as stable output. Describe it as no additional environmental effect from repeated invocation.

### Error Handling: `McpError` vs `isError`

Use `isError: true` for:

- invalid path
- path outside allowed roots
- path not found
- invalid URL or blocked URL
- invalid timeout
- unsupported report format
- invalid APP principle
- findings array validation
- scanner unavailable or external API failure when the scan cannot produce a usable result

Keep `McpError` for:

- unknown tool
- malformed JSON-RPC or request not matching `CallToolRequest`
- true server defects that should not be treated as user-correctable
- URL elicitation required protocol flow, if added later

Current:

```ts
throw new McpError(ErrorCode.InvalidParams, `invalid APP principle: ${String(value)}`);
```

Should become, at the tool boundary:

```ts
class ToolInputError extends Error {}

function toolError(message: string): ToolResponse {
  return {
    content: [{ type: 'text', text: message }],
    isError: true,
  };
}

server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
  try {
    return await handleToolCall(request.params.name, request.params.arguments, extra);
  } catch (error) {
    if (error instanceof ToolInputError) {
      return toolError(error.message);
    }
    if (error instanceof McpError && error.code === ErrorCode.MethodNotFound) {
      throw error;
    }
    throw error;
  }
});
```

If migrating to `McpServer`, note that SDK 1.29 already converts most tool-handler exceptions to `isError: true`. Still distinguish user-correctable errors from server defects in the app's own error classes and tests.

### Capabilities Declaration

Current:

```ts
{ capabilities: { tools: {} } }
```

Minimum improvement if staying low-level:

```ts
{ capabilities: { tools: { listChanged: false } } }
```

When adding resources:

```ts
{
  capabilities: {
    tools: { listChanged: false },
    resources: { subscribe: false, listChanged: false },
  },
}
```

When adding prompts:

```ts
{
  capabilities: {
    tools: { listChanged: false },
    resources: { subscribe: false, listChanged: false },
    prompts: { listChanged: false },
  },
}
```

Do not declare `tasks` until task-augmented tool calls are actually implemented.

### Resources

Add resources for stable compliance context:

- `attestlens://principles` - all APP/NDB definitions from `APPInfo`
- `attestlens://principles/{principle}` - one principle definition
- `attestlens://reform/provisions` - reform provisions, if stable enough

Example:

```ts
server.registerResource(
  'app-principles',
  'attestlens://principles',
  {
    title: 'APP/NDB Principle Definitions',
    description: 'Australian Privacy Principle and Notifiable Data Breach definitions used by AttestLens.',
    mimeType: 'application/json',
  },
  async (uri) => ({
    contents: [{
      uri: uri.href,
      mimeType: 'application/json',
      text: JSON.stringify(APPInfo, null, 2),
    }],
  }),
);
```

Do not expose arbitrary project files as resources. The scan tools already read the project, and file resources would broaden the privacy surface.

### Prompts

Add a small prompt set after resources:

- `attestlens_compliance_review` - tells the agent to run scan/check/opinion and produce a reviewer-ready summary.
- `attestlens_app11_security_review` - focused APP 11 remediation triage.
- `attestlens_reform_review` - focused Privacy Act reform impact review.

Prompts should not replace tools. They should standardize user-controlled workflows and reduce prompt drift.

### Elicitation

Do not add elicitation to the current scan-only tools.

Good future use:

- an `attestlens_attest` MCP workflow that asks non-sensitive questionnaire facts through form elicitation
- URL mode for third-party auth or sensitive configuration if AttestLens later becomes remote/SaaS

Constraints:

- form elicitation must not request secrets, credentials, or sensitive information
- form schemas are intentionally simple and flat
- URL elicitation requires state binding and user identity controls

### Tasks

Defer for npm launch unless long scans are already timing out in target clients.

SDK 1.29 supports experimental task APIs, but adoption adds state, TTL, polling, cancellation, result storage, and tests. Before tasks, wire cancellation and progress notifications.

When adopted:

```ts
server.experimental.tasks.registerToolTask('attestlens_audit', {
  title: 'Full Compliance Audit',
  description: 'Long-running APP/NDB audit.',
  outputSchema: auditOutputSchema,
  annotations: OPEN_WORLD_READ_ONLY_ANNOTATIONS,
  execution: { taskSupport: 'optional' },
}, auditTaskHandler);
```

### Security: Path Traversal And Allowed Roots

Current path protection is a good start but not sufficient as the production boundary:

- optional allowed roots means fail-open by default
- `path.resolve` should be upgraded to `fs.realpath`
- `:` should become `path.delimiter`
- shell metacharacter rejection is not the main security control and blocks valid Windows paths
- MCP Roots support should be considered for editor workspace consent

URL security is stronger than the gap analysis implies. The MCP entry point only checks protocol, but `UrlScanAdapter` uses guarded fetches, manual redirects, DNS lookup, private IP checks, localhost checks, body-size limits, and redirect validation. Keep tests around those controls.

### Transport: stdio vs Streamable HTTP

Keep stdio for npm launch and local AI editor integration.

Add Streamable HTTP only when AttestLens needs:

- a remote shared service
- web dashboard integration
- multi-user/team scans
- central auth, quotas, or observability
- gateway deployment

If adding HTTP, the 2025-11-25 transport spec requires or recommends:

- single MCP endpoint supporting POST and optionally GET
- `Origin` validation with HTTP 403 on invalid origins
- localhost binding for local HTTP
- proper auth for non-local remote access
- session ID handling if stateful
- `MCP-Protocol-Version` handling
- rate limiting and structured audit logs

Do not expose a local unauthenticated HTTP MCP server bound to `0.0.0.0`.

## SDK 1.29 Compatibility Findings

Verified in installed SDK files:

| Feature | SDK 1.29 support | Evidence |
|---|---:|---|
| `outputSchema` on tools | Yes | `ToolSchema` includes `outputSchema`; `McpServer.registerTool` accepts `outputSchema`. |
| `structuredContent` in tool results | Yes | `CallToolResultSchema` includes `structuredContent`; client validates it when a tool has `outputSchema`. |
| Tool annotations all four boolean hints | Yes | `ToolAnnotationsSchema` includes `readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`, plus `title`. |
| `execution.taskSupport` | Yes | `ToolExecutionSchema` includes `taskSupport`; experimental task server/client APIs exist. |
| High-level `McpServer` | Yes | `server/mcp.d.ts` exposes `McpServer`, `registerTool`, `registerResource`, `registerPrompt`. |
| Resources | Yes | `registerResource` and `ResourceTemplate` are available. |
| Prompts | Yes | `registerPrompt` is available. |
| Elicitation | Yes | low-level `Server` exposes `elicitInput`; README documents form and URL elicitation. |
| Streamable HTTP | Yes | `StreamableHTTPServerTransport` and host-header validation middleware exist. |
| Low-level `Server` | Available but deprecated for normal use | SDK type comments say to use `McpServer` for the high-level API. |

APIs AttestLens should use but currently does not:

- `McpServer.registerTool`
- `McpServer.registerResource`
- `McpServer.registerPrompt`
- `ResourceTemplate`
- `outputSchema` plus `structuredContent`
- request handler `extra.signal`
- MCP progress notifications
- `experimental.tasks.registerToolTask` later, if scans need durable polling
- Streamable HTTP transport later, only with auth/origin/rate-limit hardening

## Priority-Ranked Fix List

| Priority | Fix | Effort | Launch gate? |
|---|---|---:|---:|
| P0 | Return `structuredContent` and add `outputSchema` for stable JSON tools (`check`, `compliance_check`, `map`, then scan tools) | 1-2 days | Yes |
| P0 | Convert user-correctable validation/business errors to `isError: true` | 0.5-1 day | Yes |
| P0 | Fail closed on filesystem roots; use `fs.realpath`; use `path.delimiter`; add symlink tests | 0.5-1 day | Yes |
| P1 | Migrate from low-level `Server` to `McpServer.registerTool` or reproduce equivalent SDK behavior explicitly | 1-2 days | Yes, if adding resources/prompts now |
| P1 | Normalize `attestlens_audit` to a structured output envelope | 1 day | Yes, if exposing audit as production MCP contract |
| P1 | Update package ranges to SDK `^1.29.0` and Zod `^3.25.76` or Zod 4 | 0.25 day | Yes |
| P1 | Add MCP contract tests for annotations, output schemas, structured content, `isError`, roots, symlink escapes | 1 day | Yes |
| P2 | Add APP/NDB resources | 0.5-1 day | Strongly recommended |
| P2 | Wire cancellation and progress notifications | 1 day | Recommended |
| P3 | Add compliance review prompts | 0.5 day | Optional |
| P3 | Document schema versioning and deprecation policy with golden outputs | 0.5 day | Recommended before broad npm use |
| Defer | Experimental task support for long scans | 2-4 days | Not for first npm launch unless client timeouts force it |
| Defer | Streamable HTTP transport | 2-5 days | Only for remote/shared deployment |
| Defer | Rate limiting | 0.5-1 day | Required with HTTP |
| Defer | Elicitation for questionnaire attestations | 2-4 days | Separate product workflow |

## Failure Matrix

| Risk | Current posture | Failure mode | Priority |
|---|---|---|---|
| Tool output only as JSON text | All tools return `content[0].text` | Agents parse strings inconsistently; clients cannot validate results | P0 |
| User-correctable errors as protocol errors | Many `McpError(InvalidParams)` throws | Model cannot see actionable correction text | P0 |
| Filesystem boundary fail-open | No env means no root restriction | Agent can request scans of unrelated readable local directories | P0 |
| Symlink escape | Compares resolved paths, not real paths | Allowed root can contain symlink to outside data | P0 |
| SDK API drift | Uses deprecated low-level API for normal server | Manual handlers miss modern features and validation behavior | P1 |
| Polymorphic audit result | One tool returns JSON, text, HTML, PDF envelope | Static `outputSchema` becomes dishonest or too loose | P1 |
| Long scan cancellation | MCP request signal ignored | Client cancellation does not stop underlying scans | P2 |
| Progress visibility | Orchestrator progress not sent over MCP | Long scans look hung; clients may timeout | P2 |
| URL scan SSRF | Strong adapter-level guarded fetch | Main residual risk is regression, DNS TOCTOU, and future HTTP exposure | P2 test coverage |
| Lethal trifecta composition | Server lacks egress but reads private/untrusted data | Other tools in same session can complete exfiltration path | P1 output minimization |

## Recommended Implementation Shape

### Phase 1: Contract hardening

- Add `ToolInputError` and `jsonToolResult`.
- Add all four boolean annotations.
- Add output schemas and structured results for `attestlens_check`, `attestlens_compliance_check`, and `attestlens_map`.
- Convert their tests from parsing text only to asserting `structuredContent`.
- Convert validation errors to `isError: true`.

### Phase 2: Filesystem boundary

- Default allowed root to `process.cwd()` when env and client roots are absent.
- Support `ATTESTLENS_ALLOWED_ROOTS` with `path.delimiter`.
- Use `fs.realpath` on both target and roots.
- Add symlink and outside-root tests.
- Keep output path sanitization tests.

### Phase 3: SDK alignment

- Migrate to `McpServer`.
- Use Zod schemas for inputs and outputs.
- Register static APP/NDB resources.
- Keep the stdio binary behavior unchanged.

### Phase 4: Audit envelope and full schema coverage

- Normalize `attestlens_audit` output.
- Add schemas for scan, scan_url, opinion, reform, and audit.
- Add golden output contract fixtures for npm compatibility.

### Phase 5: Optional workflow polish

- Add prompts for compliance review workflows.
- Add progress notifications and cancellation.
- Consider tasks if real clients hit timeout limits.
- Add HTTP only when there is a remote service/gateway need.

