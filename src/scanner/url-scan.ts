/**
 * AttestLens — URL Scanner Adapter
 * 
 * Scans deployed websites for security vulnerabilities:
 * - Missing security headers
 * - Exposed API keys in JS bundles
 * - Infrastructure misconfigurations (.git, .env, debug endpoints)
 * - JavaScript vulnerability patterns (XSS, eval, etc.)
 * - SSL/TLS issues
 * - CORS misconfigurations
 * 
 * Uses Node.js built-in fetch — zero external dependencies.
 */

import crypto from 'node:crypto';
import { URL } from 'node:url';
import type { AttestLensFinding, ScanSource, Severity } from '../schema/index.js';
import type { ScannerAdapter, ScannerResult, ScannerError } from './types.js';
import { HEADER_CHECKS } from './rules/url-headers.js';
import { KEY_PATTERNS } from './rules/exposed-keys.js';
import { INFRA_CHECKS } from './rules/infra-checks.js';
import { JS_PATTERNS } from './rules/js-analysis.js';

const USER_AGENT = 'AttestLens/0.2.0 (Security Scanner; +https://attestlens.dev)';
const REQUEST_TIMEOUT = 30_000; // 30s per page
const JS_TIMEOUT = 10_000; // 10s per JS bundle
const MAX_HTML_SIZE = 5 * 1024 * 1024; // 5MB HTML limit
const MAX_TOTAL_JS_SIZE = 10 * 1024 * 1024; // 10MB total JS limit
const PROBE_DELAY_MS = 500; // 500ms between infrastructure probes
const MAX_REDIRECTS = 5;
const MAX_CONCURRENT_JS_FETCHES = 5; // Limit concurrent JS bundle fetches

// ─── SSRF Protection ─────────────────────────────────────────────────────────
// Reject URLs that resolve to private/internal IPs to prevent SSRF attacks.
// Covers: loopback (127.0.0.0/8), link-local (169.254.0.0/16),
// RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), and IPv6 equivalents.
const PRIVATE_IP_REGEX = /^0\.|127\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.|\[::1?\]|\[fe80:/i;

export class UrlScanAdapter implements ScannerAdapter {
  readonly name: ScanSource = 'url-scan';
  readonly version = '1.0.0';

  async isAvailable(): Promise<boolean> {
    return true; // URL scanning always available (uses built-in fetch)
  }

  async getVersion(): Promise<string> {
    return this.version;
  }

  async scan(targetPath: string): Promise<ScannerResult> {
    const startTime = Date.now();
    const findings: AttestLensFinding[] = [];
    const errors: ScannerError[] = [];

    // Validate URL
    let targetUrl: URL;
    try {
      targetUrl = new URL(targetPath);
      if (!['http:', 'https:'].includes(targetUrl.protocol)) {
        throw new Error(`Unsupported protocol: ${targetUrl.protocol}`);
      }
      // SSRF protection: reject URLs with private/internal hostnames
      if (PRIVATE_IP_REGEX.test(targetUrl.hostname)) {
        throw new Error(`Target resolves to a private/internal IP: ${targetUrl.hostname}. SSRF protection.`);
      }
    } catch (err: any) {
      return {
        source: this.name,
        version: this.version,
        timestamp: new Date().toISOString(),
        findings: [],
        errors: [{ source: this.name, message: `Invalid URL: ${err.message}`, code: 'INVALID_URL', recoverable: false }],
        durationMs: Date.now() - startTime,
      };
    }

    try {
      // 1. Fetch main page + headers
      const pageResult = await this.fetchPage(targetUrl);
      if (!pageResult) {
        return {
          source: this.name,
          version: this.version,
          timestamp: new Date().toISOString(),
          findings: [],
          errors: [{ source: this.name, message: `Failed to fetch ${targetUrl.href}`, code: 'FETCH_FAILED', recoverable: true }],
          durationMs: Date.now() - startTime,
        };
      }

      const { response, headers, html } = pageResult;

      // 2. Check security headers
      findings.push(...this.checkHeaders(headers, targetUrl.href));

      // 3. Check CORS
      findings.push(...this.checkCORS(headers, targetUrl.href));

      // 4. Extract and fetch JS bundles (with concurrency limit)
      const scriptUrls = this.extractScriptUrls(html, targetUrl);
      let totalJsSize = 0;
      const jsContents: Map<string, string> = new Map();

      // Fetch JS bundles with concurrency limit to avoid resource exhaustion
      const jsQueue = [...scriptUrls];
      const jsResults = await this.fetchJsWithConcurrency(jsQueue, MAX_CONCURRENT_JS_FETCHES, JS_TIMEOUT);
      for (const [url, content] of jsResults) {
        if (totalJsSize + content.length > MAX_TOTAL_JS_SIZE) break;
        totalJsSize += content.length;
        jsContents.set(url, content);
      }

      // 5. Check inline scripts
      const inlineScripts = this.extractInlineScripts(html);
      for (const script of inlineScripts) {
        jsContents.set('inline', jsContents.get('inline') + '\n' + script || script);
      }

      // 6. Scan JS content for exposed keys
      for (const [sourceUrl, content] of jsContents) {
        findings.push(...this.scanForKeys(content, sourceUrl, targetUrl.href));
        findings.push(...this.scanForJSPatterns(content, sourceUrl, targetUrl.href));
      }

      // 7. Also scan HTML for keys
      findings.push(...this.scanForKeys(html, targetUrl.href, targetUrl.href));

      // 8. Check infrastructure probes
      for (const check of INFRA_CHECKS) {
        await this.probeInfra(check, targetUrl, findings);
        await this.sleep(PROBE_DELAY_MS); // Rate limit probes
      }

      // 9. Check source maps
      findings.push(...await this.checkSourceMaps(scriptUrls, targetUrl.href));

      // 10. Check cookie flags
      findings.push(...this.checkCookies(headers, targetUrl.href));

      // 11. SSL/TLS check (HTTPS only)
      if (targetUrl.protocol === 'https:') {
        findings.push(...this.checkSSL(targetUrl));
      }

    } catch (err: any) {
      errors.push({
        source: this.name,
        message: `URL scan error: ${err.message}`,
        code: 'SCAN_ERROR',
        recoverable: true,
      });
    }

    // Deduplicate findings
    const deduplicated = this.deduplicate(findings);

    return {
      source: this.name,
      version: this.version,
      timestamp: new Date().toISOString(),
      findings: deduplicated,
      errors,
      durationMs: Date.now() - startTime,
    };
  }

  // ─── Header Checks ─────────────────────────────────────────────────────

  private checkHeaders(headers: Headers, url: string): AttestLensFinding[] {
    const findings: AttestLensFinding[] = [];

    for (const check of HEADER_CHECKS) {
      const value = headers.get(check.header) ?? undefined;
      if (!check.validate(value)) {
        findings.push(this.createFinding({
          sourceRule: check.id,
          severity: check.severity,
          category: 'Security Headers',
          title: value ? `${check.title} (Misconfigured)` : check.title,
          description: check.description,
          fixPrompt: check.fixPrompt,
          url,
        }));
      }
    }

    return findings;
  }

  // ─── CORS Check ─────────────────────────────────────────────────────────

  private checkCORS(headers: Headers, url: string): AttestLensFinding[] {
    const findings: AttestLensFinding[] = [];
    const acao = headers.get('access-control-allow-origin');

    if (acao === '*') {
      findings.push(this.createFinding({
        sourceRule: 'AL-URL-013',
        severity: 'medium',
        category: 'CORS',
        title: 'Wildcard CORS Configuration',
        description: 'Access-Control-Allow-Origin is set to "*", allowing any origin to make cross-origin requests. This can expose user data to malicious websites.',
        fixPrompt: `Restrict CORS to specific trusted origins:

\`\`\`typescript
// Instead of:
res.setHeader('Access-Control-Allow-Origin', '*');

// Use:
const allowedOrigins = ['https://yoursite.com', 'https://app.yoursite.com'];
const origin = req.headers.origin;
if (allowedOrigins.includes(origin)) {
  res.setHeader('Access-Control-Allow-Origin', origin);
}
\`\`\`

This addresses APP 11.1 (Security) and APP 6.1 (Use/Disclosure).`,
        url,
      }));
    }

    return findings;
  }

  // ─── Key Detection ──────────────────────────────────────────────────────

  private scanForKeys(content: string, sourceUrl: string, pageUrl: string): AttestLensFinding[] {
    const findings: AttestLensFinding[] = [];
    // Truncate content for regex scanning to prevent ReDoS on very large inputs
    const scanContent = content.length > 1_000_000 ? content.substring(0, 1_000_000) : content;

    for (const pattern of KEY_PATTERNS) {
      // Reset lastIndex for global regex
      pattern.pattern.lastIndex = 0;
      const matches = pattern.pattern.exec(scanContent);

      if (matches) {
        // Check exclusion patterns
        if (pattern.excludePattern) {
          pattern.excludePattern.lastIndex = 0;
          if (pattern.excludePattern.test(matches[0])) continue;
        }

        // Avoid false positives from common test/placeholder patterns
        if (/YOUR_|EXAMPLE|PLACEHOLDER|REPLACE|TODO|FIXME/i.test(matches[0])) {
          continue;
        }

        findings.push(this.createFinding({
          sourceRule: pattern.id,
          severity: pattern.severity,
          category: 'Exposed Keys',
          title: pattern.title,
          description: pattern.description,
          fixPrompt: pattern.fixPrompt,
          url: sourceUrl,
          code: this.truncateMatch(matches[0]),
        }));
      }
    }

    return findings;
  }

  // ─── JS Pattern Analysis ────────────────────────────────────────────────

  private scanForJSPatterns(content: string, sourceUrl: string, pageUrl: string): AttestLensFinding[] {
    const findings: AttestLensFinding[] = [];
    const isMinified = sourceUrl.endsWith('.min.js') || content.split('\n').length < 10;
    // Truncate content for regex scanning to prevent ReDoS
    const scanContent = content.length > 1_000_000 ? content.substring(0, 1_000_000) : content;

    for (const pattern of JS_PATTERNS) {
      // Skip patterns that should only match non-minified code
      if (pattern.skipMinified && isMinified) continue;

      pattern.pattern.lastIndex = 0;
      const matches = pattern.pattern.exec(scanContent);

      if (matches) {
        findings.push(this.createFinding({
          sourceRule: pattern.id,
          severity: pattern.severity,
          category: 'JS Security',
          title: pattern.title,
          description: pattern.description,
          fixPrompt: pattern.fixPrompt,
          url: sourceUrl,
          code: this.truncateMatch(matches[0]),
        }));
      }
    }

    return findings;
  }

  // ─── Infrastructure Probes ──────────────────────────────────────────────

  private async probeInfra(check: InfraCheck, baseUrl: URL, findings: AttestLensFinding[]): Promise<void> {
    try {
      const checkUrl = new URL(check.path, baseUrl).href;
      const response = await this.fetchWithTimeout(checkUrl, REQUEST_TIMEOUT, check.method);

      if (response && check.vulnerableStatuses.includes(response.status)) {
        // Verify content patterns if specified
        if (check.contentPatterns && check.contentPatterns.length > 0) {
          const body = response.text;
          const hasPattern = check.contentPatterns.some(p => p.test(body));
          if (!hasPattern) return; // Status matched but content didn't — not vulnerable
        }

        findings.push(this.createFinding({
          sourceRule: check.id,
          severity: check.severity,
          category: 'Infrastructure',
          title: check.title,
          description: check.description,
          fixPrompt: check.fixPrompt,
          url: checkUrl,
        }));
      }
    } catch {
      // Probe failed (network error, timeout, etc.) — skip
    }
  }

  // ─── Source Map Check ────────────────────────────────────────────────────

  private async checkSourceMaps(scriptUrls: string[], pageUrl: string): Promise<AttestLensFinding[]> {
    const findings: AttestLensFinding[] = [];

    for (const scriptUrl of scriptUrls.slice(0, 10)) { // Check first 10 scripts
      try {
        const mapUrl = scriptUrl + '.map';
        const response = await fetch(mapUrl, {
          headers: { 'User-Agent': USER_AGENT },
          signal: AbortSignal.timeout(5000),
        });

        if (response.ok) {
          findings.push(this.createFinding({
            sourceRule: 'AL-JS-007',
            severity: 'low',
            category: 'JS Security',
            title: 'JavaScript Source Map Available',
            description: JS_PATTERNS.find(p => p.id === 'AL-JS-007')!.description,
            fixPrompt: JS_PATTERNS.find(p => p.id === 'AL-JS-007')!.fixPrompt,
            url: mapUrl,
          }));
          break; // One source map finding is enough
        }
      } catch {
        // Skip
      }
    }

    return findings;
  }

  // ─── Cookie Flags Check ─────────────────────────────────────────────────

  private checkCookies(headers: Headers, url: string): AttestLensFinding[] {
    const findings: AttestLensFinding[] = [];
    // Use getSetCookie() when available (Node 20.6+) for proper multi-cookie handling.
    // headers.get('set-cookie') merges multiple Set-Cookie headers with commas, which
    // breaks cookie parsing since cookie values can contain commas (e.g., Expires dates).
    const rawCookies: string[] = typeof headers.getSetCookie === 'function'
      ? headers.getSetCookie()
      : (headers.get('set-cookie') ? [headers.get('set-cookie')!] : []);
    const cookies = Array.isArray(rawCookies) ? rawCookies : [rawCookies];

    for (const cookie of cookies) {
      if (!cookie) continue;
      const cookieName = cookie.split('=')[0]?.trim();
      const hasSecure = /;\s*secure/i.test(cookie);
      const hasHttpOnly = /;\s*httponly/i.test(cookie);
      const hasSameSite = /;\s*samesite/i.test(cookie);

      if (!hasSecure && url.startsWith('https://')) {
        findings.push(this.createFinding({
          sourceRule: 'AL-URL-014',
          severity: 'medium',
          category: 'Cookie Security',
          title: `Cookie "${cookieName}" Missing Secure Flag`,
          description: `The cookie "${cookieName}" is set without the Secure flag. On HTTPS sites, cookies without Secure can be sent over insecure connections during protocol downgrade attacks.`,
          fixPrompt: `Add the Secure flag to all cookies set on HTTPS sites:

\`\`\`typescript
// Express:
res.cookie('session', token, { secure: true, httpOnly: true, sameSite: 'strict' });

// Next.js:
response.setHeader('Set-Cookie', 'session=token; Secure; HttpOnly; SameSite=Strict');
\`\`\`

This addresses APP 11.1 (Security).`,
          url,
        }));
      }

      if (!hasHttpOnly) {
        findings.push(this.createFinding({
          sourceRule: 'AL-URL-015',
          severity: 'medium',
          category: 'Cookie Security',
          title: `Cookie "${cookieName}" Missing HttpOnly Flag`,
          description: `The cookie "${cookieName}" is set without the HttpOnly flag. JavaScript can access this cookie, making it vulnerable to XSS theft.`,
          fixPrompt: `Add the HttpOnly flag to session and authentication cookies:

\`\`\`typescript
res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'strict' });
\`\`\`

This addresses APP 11.1 (Security).`,
          url,
        }));
      }
    }

    return findings;
  }

  // ─── SSL/TLS Check ──────────────────────────────────────────────────────

  private checkSSL(url: URL): AttestLensFinding[] {
    // Basic SSL check — we already know it's HTTPS if we got here
    // More detailed checks would require node:tls, but fetch already validates certs
    const findings: AttestLensFinding[] = [];

    // If we successfully fetched with HTTPS, the basic SSL is working
    // We can add more checks here in the future (HSTS preload, cert expiry, etc.)

    return findings;
  }

  // ─── Helper Methods ─────────────────────────────────────────────────────

  private async fetchJsWithConcurrency(
    urls: string[],
    concurrency: number,
    timeoutMs: number,
  ): Promise<Map<string, string>> {
    const results = new Map<string, string>();
    let index = 0;

    const worker = async () => {
      while (index < urls.length) {
        const url = urls[index++];
        try {
          const response = await this.fetchWithTimeout(url, timeoutMs);
          if (response && response.text) {
            results.set(url, response.text);
          }
        } catch {
          // Skip failed JS bundles
        }
      }
    };

    const workers = Array.from({ length: Math.min(concurrency, urls.length) }, () => worker());
    await Promise.all(workers);
    return results;
  }

  private async fetchPage(url: URL): Promise<{ response: Response; headers: Headers; html: string } | null> {
    try {
      const response = await fetch(url.href, {
        headers: {
          'User-Agent': USER_AGENT,
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.5',
        },
        signal: AbortSignal.timeout(REQUEST_TIMEOUT),
        redirect: 'follow',
      });

      if (!response.ok) {
        return null;
      }

      const html = await response.text();
      if (html.length > MAX_HTML_SIZE) {
        return null; // Skip oversized pages
      }

      return { response, headers: response.headers, html };
    } catch {
      return null;
    }
  }

  private extractScriptUrls(html: string, baseUrl: URL): string[] {
    const urls: string[] = [];
    const scriptSrcRegex = /<script[^>]+src\s*=\s*["']([^"']+)["']/gi;
    let match;

    while ((match = scriptSrcRegex.exec(html)) !== null) {
      try {
        const src = match[1];
        const absoluteUrl = new URL(src, baseUrl).href;
        if (absoluteUrl.endsWith('.js') || absoluteUrl.includes('.js?')) {
          urls.push(absoluteUrl);
        }
      } catch {
        // Skip invalid URLs
      }
    }

    return urls;
  }

  private extractInlineScripts(html: string): string[] {
    const scripts: string[] = [];
    const inlineRegex = /<script[^>]*>([\s\S]*?)<\/script>/gi;
    let match;

    while ((match = inlineRegex.exec(html)) !== null) {
      const content = match[1].trim();
      if (content.length > 0 && !content.includes('src=')) {
        scripts.push(content);
      }
    }

    return scripts;
  }

  private async fetchWithTimeout(url: string, timeoutMs: number, method: string = 'GET'): Promise<{ status: number; text: string } | null> {
    try {
      const response = await fetch(url, {
        method,
        headers: { 'User-Agent': USER_AGENT },
        signal: AbortSignal.timeout(timeoutMs),
        redirect: 'follow',
      });

      const text = await response.text();
      return { status: response.status, text };
    } catch {
      return null;
    }
  }

  private truncateMatch(match: string): string {
    if (match.length > 100) {
      return match.substring(0, 100) + '...';
    }
    return match;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  private createFinding(params: {
    sourceRule: string;
    severity: Severity;
    category: string;
    title: string;
    description: string;
    fixPrompt: string;
    url: string;
    code?: string;
  }): AttestLensFinding {
    const id = crypto.createHash('sha256')
      .update(`${params.sourceRule}:${params.url}:${params.code || ''}`)
      .digest('hex')
      .substring(0, 16);

    return {
      id,
      source: 'url-scan' as ScanSource,
      sourceRule: params.sourceRule,
      severity: params.severity,
      category: params.category,
      title: params.title,
      description: params.description,
      url: params.url,
      code: params.code,
      fix: params.fixPrompt.split('\n')[0], // First line as quick fix
      fixPrompt: params.fixPrompt,
      appMappings: [
        {
          principle: 'APP_11',
          obligation: 'Take reasonable steps to protect personal information from misuse, interference, and loss',
          status: 'fail',
          confidence: 0.95,
          rationale: `${params.title} represents a failure to take reasonable steps to protect personal information under APP 11.1`,
        },
      ],
      evidence: {
        timestamp: new Date().toISOString(),
        scannerVersion: this.version,
        rawOutput: { url: params.url, code: params.code },
      },
    };
  }

  private deduplicate(findings: AttestLensFinding[]): AttestLensFinding[] {
    const seen = new Map<string, AttestLensFinding>();
    const severityOrder: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

    for (const finding of findings) {
      const key = `${finding.sourceRule}:${finding.url || ''}:${finding.code || ''}`;
      const existing = seen.get(key);

      if (!existing) {
        seen.set(key, finding);
      } else if ((severityOrder[finding.severity] || 0) > (severityOrder[existing.severity] || 0)) {
        seen.set(key, finding);
      }
    }

    return Array.from(seen.values());
  }
}

// Import InfraCheck type from the rules file
import type { InfraCheck } from './rules/infra-checks.js';

export default UrlScanAdapter;