# Milestone 1: URL Scanner — Detailed Plan

**Phase:** 1.5 — Close the Scanner Gap
**Estimated Duration:** 2 days
**Priority:** P0 (highest — this is CheckVibe's core feature)
**Dependencies:** Existing scanner infrastructure (schema, orchestrator, mapping engine)

---

## Objective

Add HTTP-based URL scanning to AttestLens so users can point at a deployed website and get security findings in ~30 seconds — matching CheckVibe's core capability while adding APP/NDB compliance mapping that no competitor has.

---

## Architecture

```
src/scanner/url-scan.ts          ← New adapter (implements ScannerAdapter)
src/scanner/rules/url-headers.ts ← Security header checks
src/scanner/rules/exposed-keys.ts ← API key pattern matching
src/scanner/rules/infra-checks.ts  ← Infrastructure checks (.git, .env, etc.)
src/scanner/rules/js-analysis.ts   ← JS bundle analysis (dangerouslySetInnerHTML, etc.)
```

The `UrlScanAdapter` implements the same `ScannerAdapter` interface as `GuardVibeAdapter`, `McpScanAdapter`, and `SupplyChainAdapter`. It gets registered in `ScannerOrchestrator` and runs in parallel with other scanners.

---

## Scanner Flow

```
URL Input
  │
  ├─► fetch(url) → response headers + HTML
  │    ├─► Security Headers (12 checks)
  │    ├─► SSL/TLS check (via https module)
  │    └─► CORS check
  │
  ├─► Parse HTML → extract <script src> + inline scripts
  │    └─► Fetch each JS bundle
  │         ├─► Exposed Key Detection (15+ patterns)
  │         ├─► JS Pattern Analysis (dangerouslySetInnerHTML, eval, etc.)
  │         └─► Source Map check
  │
  ├─► Infrastructure Probes
  │    ├─► .git/HEAD exposure
  │    ├─► .env exposure
  │    ├─► /api/debug endpoints
  │    ├─► Server version disclosure
  │    └─► Cookie flags (Secure, HttpOnly, SameSite)
  │
  └─► Normalize findings → AttestLensFinding[]
       └─► Map to APP/NDB obligations
```

---

## File-by-File Implementation Plan

### 1. `src/scanner/rules/url-headers.ts`

Security header checks — the lowest-hanging fruit and highest visual impact for users.

```typescript
interface HeaderCheck {
  id: string;          // e.g., "AL-URL-001"
  header: string;      // Header name
  severity: Severity;
  title: string;
  description: string;
  fixPrompt: string;
  appMappings: APPMapping[];
  validate: (value: string | undefined) => boolean; // true = PASS
}
```

**12 Checks:**
| ID | Header | Severity | APP |
|---|---|---|---|
| AL-URL-001 | Content-Security-Policy | high | APP_11.1 |
| AL-URL-002 | Strict-Transport-Security | high | APP_11.1 |
| AL-URL-003 | X-Frame-Options | medium | APP_11.1 |
| AL-URL-004 | X-Content-Type-Options | low | APP_11.1 |
| AL-URL-005 | Referrer-Policy | medium | APP_6.1 |
| AL-URL-006 | Permissions-Policy | low | APP_11.1 |
| AL-URL-007 | X-XSS-Protection | info | APP_11.1 |
| AL-URL-008 | Cross-Origin-Opener-Policy | medium | APP_11.1 |
| AL-URL-009 | Cross-Origin-Resource-Policy | medium | APP_11.1 |
| AL-URL-010 | Cross-Origin-Embedder-Policy | low | APP_11.1 |
| AL-URL-011 | Cache-Control (sensitive pages) | medium | APP_11.1 |
| AL-URL-012 | Server header info disclosure | info | APP_11.1 |

### 2. `src/scanner/rules/exposed-keys.ts`

API key pattern matching in fetched JS bundles and HTML.

```typescript
interface KeyPattern {
  id: string;          // e.g., "AL-KEY-001"
  name: string;        // e.g., "OpenAI API Key"
  pattern: RegExp;
  severity: Severity;
  title: string;
  description: string;
  fixPrompt: string;
  appMappings: APPMapping[];
}
```

**15+ Patterns:**
| ID | Service | Pattern | Severity |
|---|---|---|---|
| AL-KEY-001 | OpenAI | `sk-proj-[A-Za-z0-9_-]{80,}` / `sk-[A-Za-z0-9]{48}` | critical |
| AL-KEY-002 | Stripe | `sk_live_[A-Za-z0-9]{24,99}` / `pk_live_[A-Za-z0-9]{24}` | critical |
| AL-KEY-003 | Supabase | `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+` (service_role) | critical |
| AL-KEY-004 | Firebase | `AIza[A-Za-z0-9_-]{35}` (only if Admin) | high |
| AL-KEY-005 | Anthropic | `sk-ant-api03-[A-Za-z0-9_-]{95}` | critical |
| AL-KEY-006 | AWS | `AKIA[A-Z0-9]{16}` | critical |
| AL-KEY-007 | GitHub PAT | `ghp_[A-Za-z0-9]{36}` / `gho_[A-Za-z0-9]{36}` | critical |
| AL-KEY-008 | SendGrid | `SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}` | critical |
| AL-KEY-009 | Twilio | `AC[a-z0-9]{32}` (Account SID) | high |
| AL-KEY-010 | Google | `AIza[A-Za-z0-9_-]{35}` (non-Firebase) | high |
| AL-KEY-011 | Cloudflare | `[A-Za-z0-9_-]{40}` (with CF context) | high |
| AL-KEY-012 | Private Key | `-----BEGIN (RSA \|EC \|DSA)?PRIVATE KEY-----` | critical |
| AL-KEY-013 | Generic API Key | `['"](?:api[_-]?key\|secret[_-]?key\|access[_-]?key)['"]\s*[:=]\s*['"][^'"]{8,}` | medium |
| AL-KEY-014 | JWT Secret | `['"](?:jwt[_-]?secret\|token[_-]?secret)['"]\s*[:=]\s*['"][^'"]{8,}` | high |
| AL-KEY-015 | Database URL | `(?:postgres\|mysql\|mongodb)(?:\+[A-Za-z]+)?://[^\s'"]+` | critical |

### 3. `src/scanner/rules/infra-checks.ts`

Infrastructure probes — check for common misconfigurations.

```typescript
interface InfraCheck {
  id: string;
  path: string;          // URL path to probe
  method: string;        // HTTP method
  expectedStatus: number; // Status that indicates vulnerability
  severity: Severity;
  title: string;
  description: string;
  fixPrompt: string;
  appMappings: APPMapping[];
}
```

**8 Checks:**
| ID | Path | Severity | APP |
|---|---|---|---|
| AL-INFRA-001 | `/.git/HEAD` | critical | APP_11.1 |
| AL-INFRA-002 | `/.env` | critical | APP_11.1 |
| AL-INFRA-003 | `/.env.local` | critical | APP_11.1 |
| AL-INFRA-004 | `/.env.production` | critical | APP_11.1 |
| AL-INFRA-005 | `/api/debug` | high | APP_11.1 |
| AL-INFRA-006 | `/wp-admin` | medium | APP_11.1 |
| AL-INFRA-007 | `/swagger.json` | medium | APP_5.1 |
| AL-INFRA-008 | `/api/docs` | medium | APP_5.1 |

### 4. `src/scanner/rules/js-analysis.ts`

JS bundle pattern analysis — detect dangerous patterns in client-side code.

```typescript
interface JSPattern {
  id: string;
  pattern: RegExp;
  severity: Severity;
  title: string;
  description: string;
  fixPrompt: string;
  appMappings: APPMapping[];
}
```

**8 Patterns:**
| ID | Pattern | Severity | APP |
|---|---|---|---|
| AL-JS-001 | `dangerouslySetInnerHTML` | high | APP_11.1 |
| AL-JS-002 | `eval(` | high | APP_11.1 |
| AL-JS-003 | `document.write(` | medium | APP_11.1 |
| AL-JS-004 | `innerHTML` | medium | APP_11.1 |
| AL-JS-005 | `window.location` injection | medium | APP_11.1 |
| AL-JS-006 | `postMessage` without origin check | medium | APP_11.1 |
| AL-JS-007 | Source map available (`.js.map`) | low | APP_11.1 |
| AL-JS-008 | `console.log` in production | info | APP_11.1 |

### 5. `src/scanner/url-scan.ts`

Main adapter that orchestrates all URL scan checks.

```typescript
export class UrlScanAdapter implements ScannerAdapter {
  readonly name: ScanSource = 'url-scan';  // Need to add to ScanSource enum
  readonly version = '1.0.0';

  async isAvailable(): Promise<boolean> {
    return true;  // URL scanning always available (uses built-in fetch)
  }

  async scan(targetPath: string): Promise<ScannerResult> {
    // targetPath is treated as URL for this adapter
    // Or: accept URL via config flag
    // ...
  }

  async getVersion(): Promise<string> {
    return this.version;
  }

  private async fetchAndAnalyze(url: string): Promise<AttestLensFinding[]> {
    // 1. Fetch URL → headers + HTML
    // 2. Check security headers
    // 3. Parse HTML → extract script URLs
    // 4. Fetch JS bundles → pattern match
    // 5. Infrastructure probes
    // 6. SSL/TLS check
    // 7. Normalize findings
  }
}
```

**Key design decisions:**
- `isAvailable()` always returns `true` — uses Node.js built-in `fetch`, no external deps
- `targetPath` can be a URL (detected by `http://` or `https://` prefix)
- Respects `robots.txt` by default (configurable)
- Rate-limits infrastructure probes (1 probe/500ms to avoid DoS)
- Timeout: 30s per URL, 10s per JS bundle
- User-Agent: `AttestLens/0.2.0 (Security Scanner; +https://attestlens.dev)`

---

## Schema Changes

### `src/schema/index.ts`

Add `'url-scan'` to `ScanSource` enum:
```typescript
export const ScanSource = z.enum([
  'guardvibe',
  'vibesafe',
  'mcp-scan',
  'vibe-check',
  'supply-chain',
  'url-scan',      // ← NEW
  'manual',
  'questionnaire',
]);
```

### `src/scanner/orchestrator.ts`

Register `UrlScanAdapter`:
```typescript
import { UrlScanAdapter } from './url-scan.js';

constructor() {
  this.register(new GuardVibeAdapter());
  this.register(new McpScanAdapter());
  this.register(new SupplyChainAdapter());
  this.register(new UrlScanAdapter());  // ← NEW
}
```

### `src/cli/index.ts`

Add URL scan support:
```bash
# New: scan a URL directly
attestlens scan https://example.com

# Existing: scan a local directory
attestlens scan ./my-project

# New: audit a URL directly
attestlens audit https://example.com

# New: URL-only scan (no file system scanners)
attestlens scan https://example.com --url-only
```

The `scan` and `audit` commands detect URL input by checking for `http://` or `https://` prefix. When a URL is detected:
- Enable `UrlScanAdapter`
- Optionally disable file-system scanners (GuardVibe, SupplyChain) since they need a local path
- Pass URL to `UrlScanAdapter.scan()`

---

## Mapping Rules

All URL scan findings map to APP_11.1 (Security of personal information) as the primary obligation, with secondary mappings:

| Category | Primary APP | Secondary APP |
|---|---|---|
| Exposed keys | APP_11.1 | APP_6.1 (Use/Disclosure) |
| Security headers | APP_11.1 | — |
| Infrastructure | APP_11.1 | APP_6.1 |
| JS patterns | APP_11.1 | APP_6.1 |
| CORS | APP_11.1 | APP_8.1 (Cross-border) |

New mapping rules added to `src/mapping/engine.ts`:
- `AL-URL-*` → APP_11.1 (Security)
- `AL-KEY-*` → APP_11.1 + APP_6.1
- `AL-INFRA-*` → APP_11.1 + APP_6.1
- `AL-JS-*` → APP_11.1

---

## Test Plan

### Unit Tests (`src/scanner/url-scan.test.ts`)

1. **Header checks:**
   - Headers present → PASS
   - Headers missing → finding with correct severity
   - Malformed HSTS → finding
   - CSP with unsafe-inline → finding

2. **Key detection:**
   - OpenAI key in JS → critical finding
   - Stripe live key → critical finding
   - Supabase service_role JWT → critical finding
   - Test key (pk_test_*) → no finding (false positive prevention)
   - Key in comment → no finding (reduce noise)

3. **Infrastructure probes:**
   - `.git/HEAD` exposed → critical finding
   - `.env` exposed → critical finding
   - 404 response → no finding
   - Rate limiting respected

4. **JS analysis:**
   - `dangerouslySetInnerHTML` → high finding
   - `eval()` → high finding
   - Source map → low finding

5. **Integration:**
   - Full URL scan against known-vulnerable test site
   - Findings normalize correctly to `AttestLensFinding` schema
   - APP mappings correct
   - Orchestrator includes URL findings with local findings (dedup works)
   - URL input detection in CLI

### Test Fixtures

Create `test/fixtures/vulnerable-site/` with:
- `index.html` — missing security headers, inline scripts with `dangerouslySetInnerHTML`
- `app.js` — contains fake Stripe key, OpenAI key, `eval()` usage
- `.env` — with `DATABASE_URL` and `API_KEY`

Use `http://localhost:3456` as test URL (spin up local server in tests).

---

## Edge Cases & Error Handling

- **Redirects:** Follow up to 5 redirects
- **Timeouts:** 30s per URL, 10s per JS bundle, configurable
- **Rate limiting:** Respect `Retry-After` header, 500ms between probes
- **Robots.txt:** Check and respect by default, `--ignore-robots` flag to override
- **HTTPS errors:** Report as findings (expired cert, self-signed, weak TLS)
- **Large pages:** Limit to 5MB HTML, 10MB total JS
- **Rate-limited targets:** Back off on 429, report as info finding
- **Offline/unreachable:** Clear error message, don't crash

---

## Success Criteria

| Criterion | Target |
|---|---|
| URL scan completes in <30s | ✅ |
| Detects 12 missing security headers | ✅ |
| Detects 15+ exposed key patterns | ✅ |
| Detects 8 infrastructure misconfigs | ✅ |
| Detects 8 JS vulnerability patterns | ✅ |
| Zero false positives on well-configured sites | ✅ |
| Works with Node.js built-in fetch (no new deps) | ✅ |
| Integrates with existing orchestrator | ✅ |
| CLI supports URL input seamlessly | ✅ |
| All findings map to APP/NDB obligations | ✅ |
| Test coverage >90% for new code | ✅ |

---

## Implementation Order

1. **Schema changes** — Add `url-scan` to ScanSource enum (5 min)
2. **Rules files** — Create all 4 rule files with patterns (1-2 hours)
3. **UrlScanAdapter** — Core adapter with fetch + analysis flow (2-3 hours)
4. **CLI changes** — URL detection, `--url-only` flag (30 min)
5. **Mapping rules** — Add AL-URL/KEY/INFRA/JS mappings to engine (30 min)
6. **Unit tests** — Header checks, key detection, infrastructure probes (2-3 hours)
7. **Integration test** — Full URL scan against test fixture (1 hour)
8. **Manual validation** — Test against real sites (1 hour)

**Total estimated time: 8-12 hours (1-2 working days)**

---

## What This Unlocks

After Milestone 1 is complete, AttestLens can:
- ✅ Point at any deployed URL and get security findings
- ✅ Match CheckVibe's core feature (URL scanning)
- ✅ Add APP/NDB compliance mapping (no competitor has this)
- ✅ Generate compliance reports from URL scans
- ✅ Combine URL findings with local scan findings

**Next milestone:** AI Fix Prompts (1 day)