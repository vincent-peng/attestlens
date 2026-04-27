# M3 — Scanner Enhancement: Deep Research & Implementation Plan

**Created:** 2026-04-26
**Status:** In progress — M3.1–M3.6 implemented; M3.7 next
**Predecessor:** M2 (Compliance Moat) — closed; M2.5 (Rule Freshness) — foundation shipped
**Goal:** Systematically enhance the core scanner layer to close competitive gaps and differentiate on compliance-relevant detection

---

## Context

M2 closed with a compliance moat (questionnaire, breach-readiness, consultant narratives, attestation validation). M2.5 shipped rule-pack foundations (typed manifests, embedded fallback, cache, `update-rules`, freshness metadata).

The scanner layer is functional but has real gaps vs. the competitive landscape. This milestone closes those gaps in priority order, ensuring every enhancement funnels through `appMappings` to produce defensible APP/NDB principle linkages — because that's AttestLens's moat, not raw detection count.

### Current Scanner Surface

| Scanner | Rules/Checks | Key Capabilities | Key Gaps |
|---------|-------------|-----------------|----------|
| **guardvibe** | 9 static regex + 335 MCP rules | XSS, secrets, debug logging, env exposure, Supabase/RLS, Firebase, Stripe, Clerk | Requires external binary; static fallback limited to 9 rules |
| **supply-chain** | 9 static rules (VS-SC-001→009) + opt-in dynamic OSV findings | Install scripts, typosquat, lockfile, manifest-only deps, new/unknown, npm audit, OSV.dev enrichment, provenance metadata | No behavioral analysis, no package maturity, no git-dep detection |
| **url-scan** | 12 headers + 8 infra + 8 JS + ~80 key patterns + SSL/TLS + CORS + source maps | SSRF-protected fetch, JS analysis, exposed secrets, infra probes | No SAST for source, no IaC, confidence scores are static |
| **mcp-scan** | External binary | MCP server config security | Requires npx; limited when absent |

**Total:** ~60 static rules + 12 header checks + 8 infra probes + 8 JS patterns + ~80 key patterns + 335 external GuardVibe rules = ~500 checks when everything's available, ~180 without external tools.

---

## Competitive Gap Analysis

### What Competitors Do That We Don't

| Capability | Semgrep | Socket.dev | Trivy | Snyk | AttestLens |
|-----------|---------|-----------|-------|------|-----------|
| Known CVE scanning | ✅ (OSS rules) | ✅ (npm audit+) | ✅ (OSV.dev) | ✅ | ✅ (npm audit + opt-in OSV.dev) |
| Behavioral supply-chain analysis | ❌ | ✅ (25+ signals) | ❌ | ⚠️ (partial) | ❌ |
| SAST/pattern analysis | ✅ (1000+ rules) | ❌ | ❌ | ✅ (Code) | ⚠️ (8 JS patterns) |
| Secret scanning (current files) | ✅ | ✅ | ✅ | ✅ | ✅ (key patterns + repo checks) |
| Secret scanning (git history) | ❌ | ❌ | ✅ | ✅ | ❌ |
| IaC misconfiguration | ❌ | ❌ | ✅ (Docker, K8s, TF, CF) | ✅ | ❌ |
| Package maturity/author signals | ❌ | ✅ (author age, downloads) | ❌ | ❌ | ⚠️ (new/unknown only) |
| Dependency confusion detection | ❌ | ✅ | ⚠️ (RFC in progress) | ❌ | ❌ |
| Manifest confusion | ❌ | ✅ | ❌ | ❌ | ❌ |

### What AttestLens Has That They Don't

- **APP/NDB compliance mapping** — every finding maps to specific Australian Privacy Principles
- **Breach-readiness scoring** — quantified NDB readiness with evidence basis
- **Consultant-grade narrative reports** — executive summary, principle narratives, remediation focus
- **Attestation workflow** — questionnaire-backed PASS/FAIL with session persistence
- **Assessment modes** — `artifact_only`, `codebase_only`, `operator_attested`

**Key insight:** Scanner parity is table stakes. Compliance mapping is the moat. Every scanner enhancement must strengthen the mapping, not just add detection volume.

---

## M3 Enhancements (Prioritized)

### M3.1 — OSV.dev Vulnerability Integration ✅

**Priority:** P0 — highest ROI, expected by every scanner competitor
**Effort:** 2 days
**Files:** `src/scanner/supply-chain.ts` (modify), `src/scanner/osv.ts` (new), `src/scanner/osv.test.ts` (new)

#### What

Enrich the existing supply-chain scanner with OSV.dev vulnerability data while preserving the public `supply-chain` source. This is opt-in through `--external-enrichment` because it sends package names and exact versions to OSV.dev. OSV.dev supports batch queries and returns vulnerability IDs in input order; AttestLens then fetches vulnerability detail records for summaries, aliases, severity, references, and fixed versions.

#### Why

- `npm audit` only checks the npm registry advisory DB — misses GitHub Security Advisories, other ecosystems
- OSV.dev returns structured severity, affected ranges, and references — richer data for compliance mapping
- Deduplication against npm audit findings improves confidence scores
- Every CVE with data exposure implications maps directly to APP_11 and potential NDB triggers

#### Specification

```
New file: src/scanner/osv.ts

interface OsvVulnerability {
  id: string;                    // e.g., "GHSA-xxxx-xxxx-xxxx"
  summary: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  affectedVersions: string[];
  fixedVersions: string[];
  references: { type: string; url: string }[];
  published: string;
}

async function queryOsvBatch(packages: Array<{name: string; version: string}>): Promise<Map<string, OsvVulnerability[]>>
```

**Implementation details:**

1. When `--external-enrichment` is enabled, batch-query exact package versions from the lockfile via `POST https://api.osv.dev/v1/querybatch`
2. Map OSV severity → AttestLens severity: `CRITICAL→critical`, `HIGH→high`, `MEDIUM→medium`, `LOW→low`
3. Fetch unique vulnerability detail records by OSV ID
4. Deduplicate against `npm audit` only when package plus advisory alias, URL, or title matches confidently
5. Emit `source: "supply-chain"` and `sourceRule: "VS-OSV-<OSV_ID>"`
6. All OSV vulnerability findings map to APP_11 (Security) with conditional NDB/APP_8 mappings when the vulnerability class supports it
7. Keep broad cross-source deduplication and `corroboratedBy` fields deferred to M3.9

**Compliance mapping rules:**

| Vulnerability Type | APP Mapping | Rationale |
|---|---|---|
| Data exposure (XSS, injection) | APP_11 + NDB | Personal data exposure risk, potential breach trigger |
| Cross-border API calls | APP_11 + APP_8 | Data sent overseas without adequate protection |
| Auth bypass | APP_11 | Failure to protect access to personal information |
| DoS | APP_11 | Availability is a security dimension under APP_11 |
| Other | APP_11 | General security obligation |

**Error handling:**

- OSV API timeout (default 10s) → recoverable warning, continue with npm audit and other supply-chain checks
- OSV API error → log error with `code: 'OSV_API_ERROR'`, `recoverable: true`
- Vulnerability detail fetch failure → emit fallback OSV finding and recoverable `OSV_DETAIL_ERROR`
- Oversized response → reject before `JSON.parse`

**Exit criteria:**

- [x] OSV.dev batch query integration passes tests with mocked responses
- [x] Vulnerability detail fetch, timeout, and oversized-response handling are covered
- [x] All OSV findings have APP_11 + conditional NDB/APP_8 mappings
- [x] Graceful degradation when OSV API is unavailable
- [x] Supply-chain adapter still works without OSV (default local scan + npm audit fallback)
- [x] OSV.dev enrichment is explicit via `--external-enrichment`
- [ ] `npm test`, `npm run lint`, `npm run build` all green

---

### M3.2 — Dependency Provenance Detection ✅

**Priority:** P0 — 2-hour quick win
**Effort:** 2 hours
**Files:** `src/scanner/supply-chain.ts` (modify), `src/scanner/supply-chain.test.ts` (modify)

#### What

Flag direct production dependencies that have no `repository` and no `homepage` field in local or npm registry metadata. Existing `VS-SC-007` and `VS-SC-008` meanings are preserved; the new provenance signal uses `VS-SC-009`.

#### Why

- Packages without source repos are a top supply-chain risk signal (Socket.dev flags this as "missing author")
- No code audit possible → can't verify APP_11 security obligations
- Maps directly to APP_11 (reasonable steps to protect) and APP_6 (use/disclosure accountability)

#### Specification

Add after dependency parsing in `supply-chain.ts`:

```typescript
// Check direct production dependencies for packages with no source repository or homepage.
for (const [depName] of Object.entries(pkg.dependencies ?? {})) {
  const lockEntry = getLockEntry(lockfile, depName);
  if (!lockEntry) continue;
  
  // Prefer node_modules/<dep>/package.json.
  // Fall back to npm registry metadata with timeout and per-scan cache when external enrichment is enabled.
}
```

**Rule:** `VS-SC-009` — No source repository or homepage
- **Severity:** `medium`
- **APP Mapping:** APP_11 (Security — no audit trail), APP_6 (Use & Disclosure — no accountability)
- **Confidence:** 0.80
- **Fix prompt:** "Consider replacing this dependency with one that has a public source repository. Packages without source repos cannot be audited for security and may be abandoned."

**Exit criteria:**

- [x] VS-SC-009 finding generated for direct production deps with no repository or homepage
- [x] Local package metadata and opt-in npm registry fallback covered
- [x] Registry failure produces recoverable warning, not a finding
- [x] No collision with existing VS-SC-007 or VS-SC-008 behavior
- [x] APP_11 + APP_6 mappings verified in mapping tests
- [ ] `npm test`, `npm run lint`, `npm run build` all green

---

### M3.3 — Dynamic Confidence Scoring

**Priority:** P1 — strengthens report defensibility for consultants
**Effort:** 1 day
**Files:** `src/scanner/rules/*.ts` (modify), `src/scanner/supply-chain.ts` (modify), `src/scanner/url-scan.ts` (modify)

#### What

Replace hardcoded confidence values with context-aware dynamic scoring that produces stronger APP mappings when evidence is stronger.

#### Why

- A typosquat with Levenshtein distance 1 is more likely malicious than distance 2
- A missing CSP header on `/auth` or `/login` is more critical than on `/about`
- A hardcoded secret in `.env` is higher confidence than one in a config template
- Consultants need defensible confidence scores to justify their assessments
- Higher confidence → stronger APP principle linkages → more defensible NDB readiness

#### Specification

```typescript
// Dynamic confidence calculator
interface ConfidenceContext {
  editDistance?: number;        // For typosquat findings
  urlPath?: string;            // For URL-scan findings
  isAuthEndpoint?: boolean;    // Derive from URL path
  fileType?: string;           // .env vs .env.example vs .ts
  isProduction?: boolean;      // Derive from NODE_ENV or URL
  sourceCount?: number;        // Number of sources confirming same finding
}

function calculateConfidence(baseConfidence: number, context: ConfidenceContext): number {
  let confidence = baseConfidence;
  
  // Typosquat: closer edit distance = higher confidence
  if (context.editDistance !== undefined) {
    confidence *= (1 - (context.editDistance * 0.15)); // distance 1 → ×0.85, distance 2 → ×0.70
  }
  
  // Auth endpoints: missing security headers are more critical
  if (context.isAuthEndpoint) {
    confidence = Math.min(1, confidence * 1.15);
  }
  
  // Multiple sources confirming same finding
  if (context.sourceCount && context.sourceCount > 1) {
    confidence = Math.min(1, confidence * (1 + (context.sourceCount - 1) * 0.1));
  }
  
  // Clamp to [0.5, 1.0]
  return Math.max(0.5, Math.min(1.0, confidence));
}
```

**Applications:**

| Finding Type | Base Confidence | Dynamic Factor |
|---|---|---|
| Typosquat (distance 1) | 0.8 | × 0.85 = 0.68 → round to 0.7 |
| Typosquat (distance 2) | 0.8 | × 0.70 = 0.56 → round to 0.6 |
| Missing CSP on `/login` | 0.7 | × 1.15 = 0.805 → round to 0.8 |
| Missing CSP on `/about` | 0.7 | stays 0.7 |
| Secret in `.env` | 0.9 | stays 0.9 |
| Secret in `.env.example` | 0.7 | × 0.8 = 0.56 → round to 0.6 |
| Vulnerability (2 sources) | 0.85 | × 1.1 = 0.935 → round to 0.95 |
| Vulnerability (1 source) | 0.85 | stays 0.85 |

**Exit criteria:**

- [ ] `calculateConfidence()` function implemented and tested
- [ ] Supply-chain typosquat findings use dynamic confidence based on edit distance
- [ ] URL-scan header findings use dynamic confidence based on endpoint type
- [ ] Cross-source deduplicated findings boost confidence
- [ ] All existing tests still pass (confidence values may shift)
- [ ] `npm test`, `npm run lint`, `npm run build` all green

---

### M3.4 — Per-Adapter Timeout and Progress Reporting

**Priority:** P1 — production reliability
**Effort:** 2 days
**Files:** `src/scanner/types.ts` (modify), `src/scanner/orchestrator.ts` (modify), `src/scanner/*.ts` (modify all adapters)

#### What

Add per-adapter timeout configuration and a progress callback to the orchestrator so scans don't hang indefinitely and long-running scans provide real-time feedback.

#### Why

- Current orchestrator runs adapters sequentially with no timeout — a hanging `npm audit` or unreachable URL blocks everything
- No progress feedback during long scans
- Production reliability requires graceful degradation, not hard failure

#### Specification

```typescript
// Updated ScannerAdapter interface
interface ScannerAdapter {
  name: ScanSource;
  version: string;
  isAvailable(): Promise<boolean>;
  getVersion(): Promise<string>;
  scan(target: string, options?: { signal?: AbortSignal }): Promise<ScannerResult>;
}

// Updated ScannerConfig
const ScannerConfig = z.object({
  // ... existing
  timeouts: z.object({
    guardvibe: z.number().default(60_000),    // 60s
    mcpScan: z.number().default(30_000),       // 30s
    supplyChain: z.number().default(120_000),  // 120s (npm audit can be slow)
    urlScan: z.number().default(60_000),       // 60s
    gitleaks: z.number().default(30_000),       // 30s (future)
  }).default({}),
});

// Progress callback
type ScanProgressCallback = (event: {
  adapter: ScanSource;
  phase: 'starting' | 'running' | 'completed' | 'timeout' | 'error';
  detail?: string;
  elapsedMs?: number;
}) => void;
```

**Orchestrator changes:**

1. Wrap each adapter's `scan()` call in `Promise.race([scan(), timeout(abortController)])`
2. On timeout, return partial results with `errors: [{ code: 'ADAPTER_TIMEOUT', recoverable: true }]`
3. Emit progress events through callback
4. Support `AbortSignal` for CLI-level cancellation (e.g., Ctrl+C)

**Exit criteria:**

- [ ] Each adapter respects `AbortSignal` and can be cancelled
- [ ] Per-adapter timeout configuration works
- [ ] Timeout produces partial results, not hard failure
- [ ] Progress callback fires at adapter start/complete/timeout/error
- [ ] CLI can cancel scans with Ctrl+C gracefully
- [ ] All existing tests pass
- [ ] `npm test`, `npm run lint`, `npm run build` all green

---

### M3.5 — Behavioral Supply-Chain Analysis ✅

**Priority:** P1 — **highest differentiation opportunity**
**Effort:** 1 week
**Files:** `src/scanner/supply-chain.ts` (modify), `src/scanner/behavioral.ts` (new), `src/scanner/behavioral.test.ts` (new)

#### What

Analyze *what packages do at runtime* — not just what they declare in manifest. This is the single biggest scanner differentiation opportunity because no compliance tool does this.

#### Why

Socket.dev built a $2B+ company on behavioral analysis. AttestLens can cover the 6 most compliance-relevant signals without Socket's infrastructure:

| Signal | Socket Detects | AttestLens (after) | APP Mapping | Rationale |
|--------|---------------|-------------------|---|---|
| `eval()` / `new Function()` | ✅ | ✅ | APP_11 | Arbitrary code execution risk |
| Network access (`fetch`, `http`) | ✅ | ✅ | APP_11 + APP_8 | Data exfiltration, cross-border transfer |
| Shell access (`child_process`) | ✅ | ✅ | APP_11 | Arbitrary command execution |
| `process.env` access | ✅ | ✅ | APP_11 + NDB | Credential/secret access |
| Obfuscated code | ✅ | ✅ | APP_11 | Intentional hiding of behavior |
| High-entropy strings | ✅ | ✅ | APP_11 + NDB | Embedded secrets |

#### Specification

```typescript
// New file: src/scanner/behavioral.ts

interface BehavioralSignal {
  id: string;               // e.g., 'VS-BH-001'
  package: string;
  version: string;
  signal: BehavioralSignalType;
  severity: Severity;
  evidence: string;         // The matching code snippet
  file: string;             // File within the package
  appMappings: APPMapping[];
}

enum BehavioralSignalType {
  EVAL_USAGE = 'eval_usage',
  NETWORK_ACCESS = 'network_access',
  SHELL_ACCESS = 'shell_access',
  ENV_ACCESS = 'env_access',
  OBFUSCATION = 'obfuscation',
  HIGH_ENTROPY = 'high_entropy',
}
```

**Detection approach:**

1. After parsing `package.json` deps, locate package source in `node_modules/<pkg>/`
2. If `node_modules` doesn't exist, skip behavioral analysis (not a blocking error)
3. Scan each dependency's source files (JS/TS only, skip test/fixtures/docs)
4. Apply regex-based pattern detection for each signal type
5. Map findings to APP principles with dynamic confidence

**Signal rules:**

```typescript
const BEHAVIORAL_PATTERNS: Record<BehavioralSignalType, RegExp[]> = {
  eval_usage: [
    /\beval\s*\(/,
    /\bnew\s+Function\s*\(/,
    /\bvm\.runIn(?:New)?Context\s*\(/,
    /\bvm\.runInThisContext\s*\(/,
  ],
  network_access: [
    /\bfetch\s*\(/,
    /\bhttp\.request\s*\(/,
    /\bhttps\.request\s*\(/,
    /\baxios\.\w+\s*\(/,
    /\bXMLHttpRequest/,
    /\bWebSocket\s*\(/,
    /\.send\s*\(/,  // Limited — only flag if near URL patterns
  ],
  shell_access: [
    /\bchild_process\.\w+\s*\(/,
    /\bexecSync\s*\(/,
    /\bexec\s*\(/,
    /\bspawn\s*\(/,
    /\bspawnSync\s*\(/,
  ],
  env_access: [
    /\bprocess\.env\b/,
  ],
  obfuscation: [
    /\batob\s*\(/,
    /\bString\.fromCharCode\s*\(/,
    /\\x[0-9a-f]{2}/i,  // Hex-encoded strings (3+ consecutive)
    /\\u[0-9a-f]{4}/i,  // Unicode escapes (3+ consecutive)
  ],
  high_entropy: [
    // Detected via Shannon entropy calculation on string literals
    // Threshold: entropy > 4.5 on strings > 16 chars
  ],
};
```

**Important constraints:**

- Only scan direct dependencies (not transitive) in v1 — transitive deps can be added later
- Skip packages in `devDependencies` by default (flag via config)
- Skip packages larger than 1MB uncompressed (performance guard)
- Skip `node_modules` that are symlinks (monorepo workspace packages)
- Add `behavioral` to `ScanSource` enum

**Compliance mapping:**

| Signal | Primary APP | Secondary APP | Confidence | Rationale |
|---|---|---|---|---|
| `eval_usage` | APP_11 | — | 0.85 | Arbitrary code execution undermines security controls |
| `network_access` | APP_11 | APP_8 | 0.75 | Data exfiltration risk; cross-border transfer without consent |
| `shell_access` | APP_11 | — | 0.90 | System command execution = total control bypass |
| `env_access` | APP_11 | NDB | 0.70 | Access to credentials/secrets = breach vector |
| `obfuscation` | APP_11 | — | 0.65 | Intentional hiding = suspicious intent |
| `high_entropy` | APP_11 | NDB | 0.60 | Likely embedded secrets = breach risk |

**Exit criteria:**

- [x] 6 behavioral signals detected in test fixtures
- [ ] False positive rate < 5% on top-100 npm packages
- [x] Graceful skip when `node_modules` absent
- [x] All findings have APP_11 + conditional secondary mappings
- [x] Performance guarded by direct dependencies only, source-size limit, symlink skip, and adapter timeout
- [x] `vitest`, `tsc --noEmit`, and `tsc` green for milestone commit

---

### M3.6 — Git History Secret Scanning ✅

**Priority:** P1 — highest consultant value (every consultant knows current-files-only is incomplete)
**Effort:** 3 days
**Files:** `src/scanner/gitleaks.ts` (new), `src/scanner/gitleaks.test.ts` (new), `src/schema/index.ts` (modify)

#### What

Integrate `gitleaks` as an opt-in scanner adapter (like `mcp-scan`) to detect secrets committed in git history — including secrets that were "deleted" but remain in history.

#### Why

- A secret committed to git and then deleted is **still exposed** in the git history
- This is the #1 gap every consultant flags: "you checked current files, but did you check git history?"
- APP_11 requires "reasonable steps to protect" — ignoring git history is not reasonable
- Gitleaks is mature (150+ detectors), fast, outputs SARIF, single binary download
- Directly strengthens NDB readiness scoring

#### Specification

```typescript
// New file: src/scanner/gitleaks.ts

class GitleaksAdapter implements ScannerAdapter {
  readonly name: ScanSource = 'gitleaks';
  readonly version = '0.2.0';
  
  async isAvailable(): Promise<boolean> {
    // Check for gitleaks binary in PATH
    try {
      const result = execSync('gitleaks version', { timeout: 5000 });
      return result.exitCode === 0;
    } catch {
      return false;
    }
  }
  
  async scan(targetPath: string, options?: { signal?: AbortSignal }): Promise<ScannerResult> {
    // 1. Validate path exists and is a git repository
    // 2. Run: gitleaks detect --source <path> --report-format sarif --report-path <tmp>
    // 3. Parse SARIF output
    // 4. Map gitleaks rule IDs to AttestLens findings
    // 5. Map to APP principles
    // 6. Return ScannerResult
  }
}
```

**SARIF to AttestLens mapping:**

```typescript
// Gitleaks rule → AttestLens category + APP mapping
const GITLEAKS_CATEGORY_MAP: Record<string, { category: string; appMappings: APPMapping[] }> = {
  'aws-access-token': { category: 'Cloud Credentials', appMappings: [
    { principle: 'APP_11', obligation: 'Security of personal information', status: 'fail', confidence: 0.95 },
    { principle: 'NDB', obligation: 'Notifiable Data Breaches', status: 'fail', confidence: 0.85 },
  ]},
  'github-pat': { category: 'Developer Credentials', appMappings: [
    { principle: 'APP_11', obligation: 'Security of personal information', status: 'fail', confidence: 0.90 },
    { principle: 'NDB', obligation: 'Notifiable Data Breaches', status: 'fail', confidence: 0.80 },
  ]},
  // ... map top 20 most common gitleaks rules
  // Default: APP_11 + NDB, confidence 0.75
};
```

**Integration pattern (same as mcp-scan):**

- Disabled by default (requires gitleaks binary)
- `ScannerConfig.gitleaks.enabled: boolean` (default: false)
- `ScannerConfig.gitleaks.path: string` (optional custom path)
- If `gitleaks` not available, adapter returns `isAvailable() = false` and is skipped

**Exit criteria:**

- [x] `GitleaksAdapter` implemented and registered in orchestrator
- [x] `ScanSource` enum updated with `'gitleaks'`
- [x] SARIF parsing handles gitleaks rule metadata, locations, fingerprints, and findings exit behavior
- [x] Common gitleaks rules mapped to APP/NDB principles
- [x] Graceful degradation when gitleaks not installed
- [x] Orchestrator includes gitleaks in registry but disables by default
- [x] Tests with mocked gitleaks output
- [x] `vitest`, `tsc --noEmit`, and `tsc` green for milestone commit

---

### M3.7 — SAST Lite: Compliance-Critical Source Patterns

**Priority:** P2 — extends detection surface meaningfully
**Effort:** 1 week
**Files:** `src/scanner/rules/sast-lite.ts` (new), `src/scanner/guardvibe.ts` (modify to include), tests

#### What

Add 20-30 high-compliance-impact SAST patterns as regex-based rules in a new rule category. Not trying to be Semgrep — just covering the patterns that map directly to APP/NDB obligations.

#### Why

- url-scan has 8 JS patterns for client-side code — but zero source-code analysis for server-side
- SAST findings directly strengthen APP_11 and APP_6 evidence
- Regex-based patterns cover the 80/20 without needing AST parsing
- These are the exact patterns consultants look for in manual code reviews

#### Specification

**Pattern categories and rules:**

```typescript
// Authentication & Session Security
'VS-SAST-001': Hardcoded credentials in source (beyond .env)
  Pattern: /(?:password|passwd|pwd|secret|token|api_key|apikey)\s*[:=]\s*["'][^"']{8,}/i
  APP: APP_11, NDB | Severity: critical

'VS-SAST-002': Insecure session configuration (missing Secure/HttpOnly/SameSite)
  Pattern: /cookie\([^)]*\)(?!.*(?:secure|httpOnly|sameSite))/i
  APP: APP_11 | Severity: high

'VS-SAST-003': Weak cryptographic algorithm
  Pattern: /(?:md5|sha1|des|rc4|blowfish)\s*\(/i
  APP: APP_11 | Severity: medium

// Injection
'VS-SAST-004': SQL injection via string concatenation
  Pattern: /(?:query|execute|raw)\s*\([^)]*\+\s*(?:req|params|query|body)/i
  APP: APP_11 | Severity: critical

'VS-SAST-005': Path traversal (unsanitized user input in file paths)
  Pattern: /(?:readFile|writeFile|createReadStream|createWriteStream|fs\.\w+)\s*\([^)]*(?:req|params|query|body)/i
  APP: APP_11 | Severity: high

'VS-SAST-006': SSRF via user-controlled URL
  Pattern: /(?:fetch|axios|http\.get|request)\s*\(\s*(?:req|params|query|body)/i
  APP: APP_11, APP_8 | Severity: high

// Data Exposure
'VS-SAST-007': Console.log of sensitive data in production code
  Pattern: /console\.\w+\s*\([^)]*(?:password|token|secret|key|auth|credential)/i
  APP: APP_11, NDB | Severity: medium

'VS-SAST-008': Prototype pollution via JSON.parse on untrusted input
  Pattern: /JSON\.parse\s*\([^)]*(?:req|params|query|body|input)/i
  APP: APP_11 | Severity: medium

'VS-SAST-009': Missing input validation (Express handler without schema)
  Pattern: /\.(?:get|post|put|delete|patch)\s*\([^)]*\)\s*(?!.*validate)/i
  APP: APP_11 | Severity: low

'VS-SAST-010': CORS misconfiguration (wildcard origin)
  Pattern: /Access-Control-Allow-Origin\s*:\s*["']?\*["']?/i
  APP: APP_11, APP_8 | Severity: high

// Data Handling
'VS-SAST-011': Sensitive data in URL parameters
  Pattern: /(?:email|phone|ssn|credit_card|tax_file_number)\s*=\s*[^&\s]+/i
  APP: APP_6, APP_11 | Severity: medium

'VS-SAST-012': Insecure data storage (localStorage for sensitive data)
  Pattern: /localStorage\.(?:setItem|set)\s*\([^)]*(?:password|token|secret|key|auth)/i
  APP: APP_11 | Severity: medium

'VS-SAST-013': Missing encryption at rest (S3/public GCS bucket)
  Pattern: /(?:s3|gcs|storage)\.\w+\.(?:upload|create|put)\s*\([^)]*(?!encrypt)/i
  APP: APP_11 | Severity: high

'VS-SAST-014': ReDoS vulnerability (catastrophic regex patterns)
  Pattern: /new RegExp\s*\(\s*["'][^"']*(?:\([^)]+\+[^)]*\)){2,}/i
  APP: APP_11 | Severity: medium

// CORS & Headers
'VS-SAST-015': Missing authentication on sensitive routes
  Pattern: /\.(?:get|post|put|delete)\s*\(\s*["']\/(?:admin|api\/(?:user|data|config))/i
  APP: APP_11, APP_6 | Severity: high

'VS-SAST-016': Error stack trace exposure in production
  Pattern: /(?:err|error|exception)\.(?:stack|message)\s*[)};]/i
  APP: APP_11 | Severity: low

'VS-SAST-017': Missing CSRF protection
  Pattern: /\.(?:post|put|delete|patch)\s*\([^)]*\)(?!.*csrf)/i
  APP: APP_11 | Severity: medium

'VS-SAST-018': Unvalidated redirect
  Pattern: /(?:redirect|res\.redirect)\s*\(\s*(?:req|params|query|body)/i
  APP: APP_11 | Severity: medium

// Privacy-Specific (directly APP-mapped)
'VS-SAST-019': Personal data collection without consent check
  Pattern: /(?:email|phone|address|name|dob)\s*[:=]\s*(?:req\.body|formData|input)/i
  APP: APP_3, APP_5 | Severity: medium

'VS-SAST-020': Data retention without expiry
  Pattern: /(?:createUser|insertUser|addUser)\s*\([^)]*\)(?!.*(?:expire|retention|ttl|delete))/i
  APP: APP_11, APP_12 | Severity: low
```

**Integration:** SAST-lite rules execute within the GuardVibe adapter (like existing repo-stack-checks). They're part of the embedded rule pack and can be updated via the rule-pack system.

**Exit criteria:**

- [ ] 20 SAST-lite patterns implemented in `src/scanner/rules/sast-lite.ts`
- [ ] All patterns have APP/NDB mappings with confidence scores
- [ ] All patterns have `fixPrompt` strings for AI remediation
- [ ] Patterns tested against real-world code samples (both true and false positive cases)
- [ ] GuardVibe adapter includes SAST-lite rules in its scan
- [ ] `npm test`, `npm run lint`, `npm run build` all green

---

### M3.8 — IaC Misconfiguration Detection

**Priority:** P2 — extends detection surface for infrastructure
**Effort:** 1 week (Dockerfile + Terraform only)
**Files:** `src/scanner/iac.ts` (new), `src/scanner/iac.test.ts` (new), rule definitions

#### What

Static analysis of Dockerfile and Terraform files for security misconfigurations that map to APP_11 obligations.

#### Why

- Trivy covers this but requires Go runtime — AttestLens can cover the top 15-20 checks per format with pure TypeScript
- Infrastructure misconfig is a major APP_11 risk (unencrypted storage, public access, overly permissive IAM)
- Maps directly to what consultants check in manual reviews

#### Specification

**Dockerfile checks (15 rules):**

| ID | Check | Severity | APP Mapping |
|---|---|---|---|
| VS-IAC-001 | Running as root | critical | APP_11 |
| VS-IAC-002 | Using ADD instead of COPY | low | APP_11 |
| VS-IAC-003 | No HEALTHCHECK defined | low | APP_11 |
| VS-IAC-004 | Exposed privileged ports (<1024) | medium | APP_11 |
| VS-IAC-005 | Secrets in ENV or ARG | critical | APP_11, NDB |
| VS-IAC-006 | Using :latest tag | medium | APP_11 |
| VS-IAC-007 | No USER instruction | high | APP_11 |
| VS-IAC-008 | apt-get without --no-install-recommends | low | APP_11 |
| VS-IAC-009 | Running apt-get update without cache cleanup | low | APP_11 |
| VS-IAC-010 | EXPOSE on well-known database ports | medium | APP_11 |
| VS-IAC-011 | Missing .dockerignore | low | APP_11 |
| VS-IAC-012 | COPY with wildcard | medium | APP_11 |
| VS-IAC-013 | Hardcoded IP addresses | medium | APP_11 |
| VS-IAC-014 | Using sudo in RUN | high | APP_11 |
| VS-IAC-015 | Writable filesystem without explicit mount | medium | APP_11 |

**Terraform checks (10 rules):**

| ID | Check | Severity | APP Mapping |
|---|---|---|---|
| VS-IAC-016 | S3 bucket without encryption | critical | APP_11 |
| VS-IAC-017 | S3 bucket with public ACL | critical | APP_11, APP_8 |
| VS-IAC-018 | RDS without encryption at rest | high | APP_11 |
| VS-IAC-019 | Security group allowing 0.0.0.0/0 | critical | APP_11 |
| VS-IAC-020 | IAM policy with full admin (*:*) | high | APP_11 |
| VS-IAC-021 | Unencrypted EBS volume | high | APP_11 |
| VS-IAC-022 | Lambda without VPC | medium | APP_11 |
| VS-IAC-023 | Missing logging configuration | medium | APP_11, APP_12 |
| VS-IAC-024 | Hardcoded secrets in variables | critical | APP_11, NDB |
| VS-IAC-025 | Missing version constraint on providers | low | APP_11 |

**Exit criteria:**

- [ ] IaC adapter detects Dockerfile and Terraform files
- [ ] 15 Dockerfile checks implemented and tested
- [ ] 10 Terraform checks implemented and tested
- [ ] All findings map to APP_11 + conditional NDB
- [ ] Graceful skip when no Dockerfile/Terraform files found
- [ ] `iac` added to `ScanSource` enum
- [ ] `npm test`, `npm run lint`, `npm run build` all green

---

### M3.9 — Cross-Scanner Finding Deduplication

**Priority:** P2 — improves report quality
**Effort:** 1 day
**Files:** `src/scanner/orchestrator.ts` (modify)

#### What

Add canonical key generation that deduplicates findings across different scanners that detect the same vulnerability (e.g., url-scan's `AL-JS-001` vs GuardVibe's `VS-XSS` both flagging `dangerouslySetInnerHTML`).

#### Why

- Same vulnerability flagged by multiple scanners clutters reports
- Consultants don't want to see 3 findings for one XSS vector
- Multiple confirmations should *boost confidence*, not *triple-count*

#### Specification

```typescript
interface CanonicalKey {
  vulnType: string;    // e.g., 'xss', 'hardcoded-secret', 'eval'
  file: string;       // Normalized file path
  line: number;       // Line number
}

function generateCanonicalKey(finding: AttestLensFinding): CanonicalKey {
  const vulnTypeMap: Record<string, string> = {
    'AL-JS-001': 'xss-dangerouslySetInnerHTML',
    'VS-XSS': 'xss-dangerouslySetInnerHTML',
    'AL-JS-002': 'eval-usage',
    'VS-HARDKEY': 'hardcoded-secret',
    'AL-KEY-001': 'aws-key-exposure',
    // ... more mappings
  };
  return {
    vulnType: vulnTypeMap[finding.sourceRule] || finding.sourceRule,
    file: finding.file?.replace(/\\/g, '/') || '',
    line: finding.line || 0,
  };
}
```

**Dedup logic in orchestrator:**

1. After all adapters complete, group findings by canonical key
2. For each group with 2+ findings:
   - Keep the finding with the highest severity
   - Add `corroboratedBy: ScanSource[]` field to indicate multi-source confirmation
   - Set confidence to max(group) + 0.05 per additional source (capped at 0.95)
3. For single-source findings, pass through unchanged

**Exit criteria:**

- [ ] Canonical key generation works for cross-scanner duplicates
- [ ] Dedup preserves the highest-severity finding
- [ ] Multi-source findings get confidence boost
- [ ] `corroboratedBy` field appears in deduplicated findings
- [ ] All existing tests still pass
- [ ] `npm test`, `npm run lint`, `npm run build` all green

---

### M3.10 — Package Maturity Scoring

**Priority:** P3 — nice-to-have signal enrichment
**Effort:** 1 day
**Files:** `src/scanner/supply-chain.ts` (modify), tests

#### What

Enrich supply-chain findings with npm package maturity signals: weekly downloads, maintainer count, publish history, README/tests presence.

#### Why

- A package with < 100 weekly downloads + single maintainer + no source repo = triple red flag
- Socket.dev uses these signals extensively; AttestLens currently only checks "new/unknown" (< 30 days)
- These signals strengthen APP_11 confidence scores for supply-chain findings

#### Specification

```typescript
interface PackageMaturity {
  name: string;
  weeklyDownloads: number;
  maintainerCount: number;
  hasReadme: boolean;
  hasTests: boolean;
  hasRepository: boolean;
  ageDays: number;
  versionCount: number;
}

// Maturity risk score: 0 (low risk) to 1 (high risk)
function calculateMaturityRisk(maturity: PackageMaturity): number {
  let risk = 0;
  if (maturity.weeklyDownloads < 100) risk += 0.3;
  else if (maturity.weeklyDownloads < 1000) risk += 0.15;
  if (maturity.maintainerCount <= 1) risk += 0.2;
  if (!maturity.hasReadme) risk += 0.1;
  if (!maturity.hasTests) risk += 0.1;
  if (!maturity.hasRepository) risk += 0.15;
  if (maturity.ageDays < 30) risk += 0.15;
  return Math.min(1, risk);
}
```

**Enhancement to existing findings:**

- VS-SC-003 (new/unknown packages): add `maturity` field to finding `evidence`
- VS-SC-004 (typosquat): boost confidence if target package has high maturity
- New finding VS-SC-010 (low-maturity dependency): risk > 0.5 triggers a finding

**Exit criteria:**

- [ ] npm registry API integration with rate limiting (10 req/s max)
- [ ] Maturity data cached for 1 hour (avoid repeated lookups)
- [ ] VS-SC-010 finding generated for high-risk packages
- [ ] Existing findings enriched with maturity data
- [ ] Graceful degradation when npm registry unavailable
- [ ] `npm test`, `npm run lint`, `npm run build` all green

---

## Implementation Timeline

```
Week 1-2 (M3.1 + M3.2 + M3.3 + M3.4):
  Day 1-2:  M3.1 — OSV.dev integration
  Day 2:    M3.2 — No-source-repo deps (quick win)
  Day 3:    M3.3 — Dynamic confidence scoring
  Day 4-5:  M3.4 — Per-adapter timeout + progress

Week 3-4 (M3.5 + M3.6):
  Day 1-5:  M3.5 — Behavioral supply-chain analysis
  Day 6-8:  M3.6 — Git history secret scanning (gitleaks)

Week 5-6 (M3.7 + M3.8):
  Day 1-5:  M3.7 — SAST lite patterns
  Day 6-10: M3.8 — IaC misconfiguration (Dockerfile + Terraform)

Week 7 (M3.9 + M3.10):
  Day 1:    M3.9 — Cross-scanner deduplication
  Day 2-3:  M3.10 — Package maturity scoring
  Day 4-5:  Buffer / integration testing / doc updates
```

---

## Schema Changes Required

### `ScanSource` enum additions

```typescript
// Current
export const ScanSource = z.enum([
  'guardvibe', 'vibesafe', 'mcp-scan', 'vibe-check',
  'supply-chain', 'url-scan', 'manual', 'questionnaire',
]);

// After M3
export const ScanSource = z.enum([
  'guardvibe', 'vibesafe', 'mcp-scan', 'vibe-check',
  'supply-chain', 'url-scan', 'manual', 'questionnaire',
  'behavioral',    // M3.5 — Behavioral supply-chain analysis
  'gitleaks',      // M3.6 — Git history secret scanning
  'sast-lite',     // M3.7 — SAST lite patterns
  'iac',           // M3.8 — IaC misconfiguration detection
]);
```

M3.1 intentionally did **not** add `osv` to `ScanSource`; OSV findings are emitted through the existing `supply-chain` source with dynamic `VS-OSV-<OSV_ID>` rule IDs. Revisit public source expansion only if M3.9 cross-scanner dedup requires it.

### `ScannerConfig` additions

These are future-facing configuration candidates. M3.1/M3.2 currently use internal adapter options and do not add public CLI/schema fields.

```typescript
export const ScannerConfig = z.object({
  // ... existing
  osv: z.object({
    enabled: z.boolean().default(true),
    timeout: z.number().default(10_000),
  }),
  behavioral: z.object({
    enabled: z.boolean().default(true),
    skipDevDeps: z.boolean().default(true),
    maxPackageSize: z.number().default(1_000_000), // 1MB
  }),
  gitleaks: z.object({
    enabled: z.boolean().default(false),
    path: z.string().optional(),
  }),
  sastLite: z.object({
    enabled: z.boolean().default(true),
  }),
  iac: z.object({
    enabled: z.boolean().default(true),
    dockerfile: z.boolean().default(true),
    terraform: z.boolean().default(true),
  }),
  timeouts: z.object({
    guardvibe: z.number().default(60_000),
    mcpScan: z.number().default(30_000),
    supplyChain: z.number().default(120_000),
    urlScan: z.number().default(60_000),
    gitleaks: z.number().default(30_000),
  }).default({}),
});
```

### `AttestLensFinding` additions

```typescript
// Add to existing schema
corroboratedBy: z.array(ScanSource).optional(),  // M3.9 — multi-source confirmation
maturity: z.object({
  weeklyDownloads: z.number().optional(),
  maintainerCount: z.number().optional(),
  risk: z.number().min(0).max(1).optional(),
}).optional(),  // M3.10 — package maturity signals
```

---

## Test Strategy

### Unit Tests

Each new adapter and rule module requires:

1. **Happy path:** Known-vulnerable fixture produces expected findings
2. **Empty path:** Clean fixture produces no findings
3. **Error path:** Invalid/missing input produces graceful errors, not crashes
4. **Mapping verification:** Every finding has at least one APP/NDB mapping
5. **Confidence bounds:** All confidence values are in [0.5, 1.0]

### Integration Tests

1. **Orchestrator:** All new adapters register correctly and can be enabled/disabled
2. **Cross-scanner dedup:** Same vulnerability from multiple sources deduplicates correctly
3. **Report output:** New finding types render correctly in JSON, HTML, Markdown, PDF
4. **CLI:** `attestlens scan` includes new findings by default; `--no-osv` / `--no-behavioral` flags work

### Regression Tests

1. Existing 223 tests continue passing
2. Existing fixture outputs unchanged (new findings are additive)
3. Rule freshness metadata still works after schema additions

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| OSV.dev API downtime | Medium | Low — falls back to npm audit | Timeout + fallback path tested |
| Behavioral scan too slow | Medium | Medium — UX degradation | Skip transitive deps, size limits, AbortSignal |
| Gitleaks not installed | High | Low — gracefully disabled | Opt-in adapter pattern (like mcp-scan) |
| SAST-lite false positives | High | Medium — report noise | Conservative patterns, severity thresholds, fix prompts |
| IaC parser fragility | Medium | Low — graceful skip on parse error | Try/catch per file, skip malformed |
| Schema changes break reports | Low | High — blocks milestone | Additive-only changes, backward compat tests |
| Package maturity API rate limit | Medium | Low — enriched finding degrades to basic | Cache + fallback |

---

## Success Metrics

| Metric | Before M3 | After M3 | Target |
|---|---|---|---|
| Total detection surface | ~180 static rules | ~250+ rules | 2x coverage on compliance-relevant vectors |
| Vulnerability sources | 1 (npm audit) | 2 with opt-in OSV.dev | CVE coverage parity with Snyk |
| Supply-chain signals | 8 | 14+ | 6 behavioral signals added |
| Secret detection | Current files only | Current + git history | Full coverage |
| SAST patterns | 8 JS (url-scan only) | 28+ (url-scan + SAST-lite) | 3.5x increase |
| IaC coverage | 0 | 25 (Dockerfile + Terraform) | Infrastructure baseline |
| Confidence scoring | Fixed | Dynamic | Consultant-defensible scores |
| Report deduplication | Rule+file+line only | Canonical key across sources | No triple-counting |
