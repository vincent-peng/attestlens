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
import { lookup } from 'node:dns/promises';
import http from 'node:http';
import https from 'node:https';
import { isIP } from 'node:net';
import { URL } from 'node:url';
import type { AttestLensFinding, ScanSource, Severity } from '../schema/index.js';
import type { ScannerAdapter, ScannerContext, ScannerResult, ScannerError } from './types.js';
import { HEADER_CHECKS } from './rules/url-headers.js';
import { KEY_PATTERNS } from './rules/exposed-keys.js';
import { INFRA_CHECKS, type InfraCheck } from './rules/infra-checks.js';
import { JS_PATTERNS } from './rules/js-analysis.js';

const USER_AGENT = 'AttestLens/0.2.0 (Security Scanner; +https://attestlens.dev)';
const REQUEST_TIMEOUT = 30_000; // 30s per page
const JS_TIMEOUT = 10_000; // 10s per JS bundle
const MAX_HTML_SIZE = 5 * 1024 * 1024; // 5MB HTML limit
const MAX_TOTAL_JS_SIZE = 10 * 1024 * 1024; // 10MB total JS limit
const PROBE_DELAY_MS = 500; // 500ms between infrastructure probes
const MAX_REDIRECTS = 5;
const DNS_PIN_ENV = 'ATTESTLENS_URL_SCAN_DNS_PIN';

interface ResolvedAddress {
  address: string;
  family: number;
}

interface GuardedFetchResult {
  status: number;
  ok: boolean;
  headers: Headers;
  text: string;
  finalUrl: URL;
  bodyExceeded: boolean;
}

interface GuardedFetchOptions {
  timeoutMs: number;
  method?: string;
  headers?: HeadersInit;
  maxBytes?: number;
  blockBehavior?: 'throw' | 'skip';
  signal?: AbortSignal;
}

class BlockedUrlError extends Error {
  readonly url: string;

  constructor(url: string, message: string) {
    super(message);
    this.name = 'BlockedUrlError';
    this.url = url;
  }
}

export class UrlScanAdapter implements ScannerAdapter {
  readonly name: ScanSource = 'url-scan';
  readonly version = '1.0.0';

  async isAvailable(): Promise<boolean> {
    return true; // URL scanning always available (uses built-in fetch)
  }

  async getVersion(): Promise<string> {
    return this.version;
  }

  async scan(targetPath: string, context?: ScannerContext): Promise<ScannerResult> {
    const startTime = Date.now();
    const findings: AttestLensFinding[] = [];
    const errors: ScannerError[] = [];

    // Validate URL syntax up front. SSRF checks happen in the guarded fetch path
    // so redirects and derived URLs use the same policy.
    let targetUrl: URL;
    try {
      targetUrl = new URL(targetPath);
      if (!['http:', 'https:'].includes(targetUrl.protocol)) {
        throw new Error(`Unsupported protocol: ${targetUrl.protocol}`);
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

    let pageResult: { headers: Headers; html: string; finalUrl: URL } | null = null;
    try {
      pageResult = await this.fetchPage(targetUrl, context?.signal);
    } catch (err: any) {
      if (err instanceof BlockedUrlError) {
        return {
          source: this.name,
          version: this.version,
          timestamp: new Date().toISOString(),
          findings: [],
          errors: [{ source: this.name, message: `Invalid URL: ${err.message}`, code: 'INVALID_URL', recoverable: false }],
          durationMs: Date.now() - startTime,
        };
      }

      return {
        source: this.name,
        version: this.version,
        timestamp: new Date().toISOString(),
        findings: [],
        errors: [{ source: this.name, message: `Failed to fetch ${targetUrl.href}`, code: 'FETCH_FAILED', recoverable: true }],
        durationMs: Date.now() - startTime,
      };
    }

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

    try {
      const { headers, html, finalUrl } = pageResult;

      // 2. Check security headers
      findings.push(...this.checkHeaders(headers, finalUrl.href));

      // 3. Check CORS
      findings.push(...this.checkCORS(headers, finalUrl.href));

      // 4. Extract and fetch JS bundles using a strict total byte budget.
      const scriptUrls = this.extractScriptUrls(html, finalUrl);
      const jsContents = await this.fetchJavaScriptBundles(scriptUrls, MAX_TOTAL_JS_SIZE, context?.signal);

      // 5. Check inline scripts
      const inlineScripts = this.extractInlineScripts(html);
      for (const script of inlineScripts) {
        const existingInline = jsContents.get('inline');
        jsContents.set('inline', existingInline ? `${existingInline}\n${script}` : script);
      }

      // 6. Scan JS content for exposed keys
      for (const [sourceUrl, content] of jsContents) {
        findings.push(...this.scanForKeys(content, sourceUrl));
        findings.push(...this.scanForJSPatterns(content, sourceUrl));
      }

      // 7. Also scan HTML for keys
      findings.push(...this.scanForKeys(html, finalUrl.href));

      // 8. Check infrastructure probes
      for (const check of INFRA_CHECKS) {
        await this.probeInfra(check, finalUrl, findings, context?.signal);
        await this.sleep(PROBE_DELAY_MS); // Rate limit probes
      }

      // 9. Check source maps
      findings.push(...await this.checkSourceMaps(scriptUrls, context?.signal));

      // 10. Check cookie flags
      findings.push(...this.checkCookies(headers, finalUrl.href));

      // 11. SSL/TLS check (HTTPS only)
      if (finalUrl.protocol === 'https:') {
        findings.push(...this.checkSSL(finalUrl));
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

  private scanForKeys(content: string, sourceUrl: string): AttestLensFinding[] {
    const findings: AttestLensFinding[] = [];
    // Truncate content for regex scanning to prevent ReDoS on very large inputs
    const scanContent = content.length > 1_000_000 ? content.substring(0, 1_000_000) : content;

    for (const pattern of KEY_PATTERNS) {
      // Reset lastIndex for global regex
      pattern.pattern.lastIndex = 0;
      let matches: RegExpExecArray | null;

      while ((matches = pattern.pattern.exec(scanContent)) !== null) {
        const matchedValue = matches[0];

        // Check exclusion patterns
        if (pattern.excludePattern) {
          pattern.excludePattern.lastIndex = 0;
          if (pattern.excludePattern.test(matchedValue)) continue;
        }

        if (pattern.matchFilter && !pattern.matchFilter(matchedValue)) {
          continue;
        }

        // Avoid false positives from common test/placeholder patterns
        if (/YOUR_|EXAMPLE|PLACEHOLDER|REPLACE|TODO|FIXME/i.test(matchedValue)) {
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
          code: this.truncateMatch(matchedValue),
        }));
        break;
      }
    }

    return findings;
  }

  // ─── JS Pattern Analysis ────────────────────────────────────────────────

  private scanForJSPatterns(content: string, sourceUrl: string): AttestLensFinding[] {
    const findings: AttestLensFinding[] = [];
    const isMinified = sourceUrl.includes('.min.js') || content.split('\n').length < 10;
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

  private async probeInfra(check: InfraCheck, baseUrl: URL, findings: AttestLensFinding[], signal?: AbortSignal): Promise<void> {
    try {
      const checkUrl = new URL(check.path, baseUrl).href;
      const response = await this.fetchGuardedText(checkUrl, {
        timeoutMs: REQUEST_TIMEOUT,
        method: check.method,
        blockBehavior: 'skip',
        signal,
      });

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

  private async checkSourceMaps(scriptUrls: string[], signal?: AbortSignal): Promise<AttestLensFinding[]> {
    const findings: AttestLensFinding[] = [];
    const sourceMapPattern = JS_PATTERNS.find(p => p.id === 'AL-JS-007');
    if (!sourceMapPattern) return findings;

    for (const scriptUrl of scriptUrls.slice(0, 10)) { // Check first 10 scripts
      try {
        const mapUrl = this.buildSourceMapUrl(scriptUrl);
        const response = await this.fetchGuardedText(mapUrl, {
          timeoutMs: 5000,
          blockBehavior: 'skip',
          signal,
        });

        if (response?.ok && !this.isHtmlResponse(response)) {
          findings.push(this.createFinding({
            sourceRule: 'AL-JS-007',
            severity: 'low',
            category: 'JS Security',
            title: sourceMapPattern.title,
            description: sourceMapPattern.description,
            fixPrompt: sourceMapPattern.fixPrompt,
            url: response.finalUrl.href,
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

  private async fetchJavaScriptBundles(
    urls: string[],
    maxTotalBytes: number = MAX_TOTAL_JS_SIZE,
    signal?: AbortSignal,
  ): Promise<Map<string, string>> {
    const results = new Map<string, string>();
    let remainingJsBudget = maxTotalBytes;

    for (const url of urls) {
      if (remainingJsBudget <= 0) break;

      const response = await this.fetchGuardedText(url, {
        timeoutMs: JS_TIMEOUT,
        maxBytes: remainingJsBudget,
        blockBehavior: 'skip',
        signal,
      });

      if (!response || !response.ok) {
        continue;
      }

      if (response.bodyExceeded) {
        break;
      }

      if (this.isHtmlResponse(response)) {
        continue;
      }

      remainingJsBudget -= Buffer.byteLength(response.text);
      results.set(response.finalUrl.href, response.text);
    }

    return results;
  }

  private async fetchPage(url: URL, signal?: AbortSignal): Promise<{ headers: Headers; html: string; finalUrl: URL } | null> {
    const response = await this.fetchGuardedText(url, {
      timeoutMs: REQUEST_TIMEOUT,
      maxBytes: MAX_HTML_SIZE,
      blockBehavior: 'throw',
      signal,
      headers: {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
      },
    });

    if (!response || !response.ok || response.bodyExceeded) {
      return null;
    }

    return { headers: response.headers, html: response.text, finalUrl: response.finalUrl };
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

  private buildSourceMapUrl(scriptUrl: string): string {
    try {
      const url = new URL(scriptUrl);
      url.pathname = `${url.pathname}.map`;
      return url.toString();
    } catch {
      return `${scriptUrl}.map`;
    }
  }

  private async fetchGuardedText(url: URL | string, options: GuardedFetchOptions): Promise<GuardedFetchResult | null> {
    const headers = new Headers(options.headers);
    headers.set('User-Agent', USER_AGENT);

    let currentUrl = typeof url === 'string' ? new URL(url) : new URL(url.href);
    let method = options.method ?? 'GET';

    for (let redirectCount = 0; redirectCount <= MAX_REDIRECTS; redirectCount++) {
      let response: Response;
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), options.timeoutMs);
      const abort = () => controller.abort();
      options.signal?.addEventListener('abort', abort, { once: true });
      try {
        const resolvedAddresses = await this.resolvePublicScanTarget(currentUrl);
        response = await this.fetchResolved(currentUrl, resolvedAddresses, {
          method,
          headers,
          signal: controller.signal,
        });
      } catch (err) {
        if (err instanceof BlockedUrlError && options.blockBehavior === 'throw') {
          throw err;
        }
        return null;
      } finally {
        clearTimeout(timeout);
        options.signal?.removeEventListener('abort', abort);
      }

      if (this.isRedirectStatus(response.status)) {
        if (redirectCount === MAX_REDIRECTS) {
          return null;
        }

        const location = response.headers.get('location');
        if (!location) {
          return null;
        }

        currentUrl = new URL(location, currentUrl);
        if (response.status === 303 && method !== 'HEAD') {
          method = 'GET';
        }
        continue;
      }

      const body = await this.readResponseText(response, options.maxBytes ?? Number.POSITIVE_INFINITY);
      return {
        status: response.status,
        ok: response.ok,
        headers: response.headers,
        text: body.text,
        finalUrl: currentUrl,
        bodyExceeded: body.bodyExceeded,
      };
    }

    return null;
  }

  private async readResponseText(
    response: Response,
    maxBytes: number,
  ): Promise<{ text: string; bodyExceeded: boolean }> {
    const contentLength = Number(response.headers.get('content-length'));
    if (Number.isFinite(maxBytes) && Number.isFinite(contentLength) && contentLength > maxBytes) {
      await response.body?.cancel();
      return { text: '', bodyExceeded: true };
    }

    if (!response.body || !Number.isFinite(maxBytes)) {
      const text = await response.text();
      if (Number.isFinite(maxBytes) && Buffer.byteLength(text) > maxBytes) {
        return { text: '', bodyExceeded: true };
      }
      return { text, bodyExceeded: false };
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let bytesRead = 0;
    let text = '';

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!value) continue;

        bytesRead += value.byteLength;
        if (bytesRead > maxBytes) {
          await reader.cancel();
          return { text: '', bodyExceeded: true };
        }

        text += decoder.decode(value, { stream: true });
      }

      text += decoder.decode();
      return { text, bodyExceeded: false };
    } finally {
      reader.releaseLock();
    }
  }

  private isRedirectStatus(status: number): boolean {
    return status === 301 || status === 302 || status === 303 || status === 307 || status === 308;
  }

  private isHtmlResponse(response: GuardedFetchResult): boolean {
    const contentType = response.headers.get('content-type')?.toLowerCase() || '';
    const trimmed = response.text.trimStart().slice(0, 64).toLowerCase();
    return contentType.includes('text/html')
      || trimmed.startsWith('<!doctype html')
      || trimmed.startsWith('<html');
  }

  private async assertPublicScanTarget(url: URL): Promise<void> {
    await this.resolvePublicScanTarget(url);
  }

  private async resolvePublicScanTarget(url: URL): Promise<ResolvedAddress[]> {
    if (!['http:', 'https:'].includes(url.protocol)) {
      throw new BlockedUrlError(url.href, `Unsupported protocol: ${url.protocol}`);
    }

    const hostname = this.normalizeHost(url.hostname);
    if (!hostname) {
      throw new BlockedUrlError(url.href, 'URL is missing a hostname');
    }

    if (this.isLocalHostname(hostname)) {
      throw new BlockedUrlError(
        url.href,
        `Target resolves to a private/internal host: ${hostname}. SSRF protection.`,
      );
    }

    if (isIP(hostname) !== 0) {
      if (!this.isPublicIpAddress(hostname)) {
        throw new BlockedUrlError(
          url.href,
          `Target resolves to a private/internal IP: ${hostname}. SSRF protection.`,
        );
      }
      return [{ address: hostname, family: isIP(hostname) }];
    }

    const addresses = await this.lookupHostname(hostname);
    // Known limitation when ATTESTLENS_URL_SCAN_DNS_PIN is false: this DNS
    // validation can pass, then the default fetch path can resolve the hostname
    // again. A rebinding host could swap to a private IP between those steps.
    for (const entry of addresses) {
      if (!this.isPublicIpAddress(entry.address)) {
        throw new BlockedUrlError(
          url.href,
          `Target resolves to a private/internal IP: ${entry.address}. SSRF protection.`,
        );
      }
    }
    if (addresses.length === 0) {
      throw new BlockedUrlError(url.href, `Target did not resolve: ${hostname}. SSRF protection.`);
    }
    return addresses;
  }

  private async fetchResolved(
    url: URL,
    resolvedAddresses: ResolvedAddress[],
    options: { method: string; headers: Headers; signal: AbortSignal },
  ): Promise<Response> {
    if (!this.isDnsPinningEnabled()) {
      return fetch(url.href, {
        method: options.method,
        headers: options.headers,
        signal: options.signal,
        redirect: 'manual',
      });
    }

    const [pinnedAddress] = resolvedAddresses;
    if (!pinnedAddress) {
      throw new BlockedUrlError(url.href, 'Target did not resolve. SSRF protection.');
    }
    return this.fetchWithPinnedDns(url, pinnedAddress, options);
  }

  private isDnsPinningEnabled(): boolean {
    const value = process.env[DNS_PIN_ENV]?.trim().toLowerCase();
    return value === '1' || value === 'true' || value === 'yes' || value === 'on';
  }

  private async fetchWithPinnedDns(
    url: URL,
    pinnedAddress: ResolvedAddress,
    options: { method: string; headers: Headers; signal: AbortSignal },
  ): Promise<Response> {
    return new Promise<Response>((resolve, reject) => {
      const client = url.protocol === 'https:' ? https : http;
      const requestHeaders = Object.fromEntries(options.headers.entries());
      const request = client.request({
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port || undefined,
        path: `${url.pathname}${url.search}`,
        method: options.method,
        headers: requestHeaders,
        lookup: (_hostname, _lookupOptions, callback) => {
          callback(null, pinnedAddress.address, pinnedAddress.family);
        },
      }, (incoming) => {
        const chunks: Buffer[] = [];
        incoming.on('data', (chunk: Buffer | string) => {
          chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        });
        incoming.on('end', () => {
          cleanup();
          const responseHeaders = new Headers();
          for (const [name, value] of Object.entries(incoming.headers)) {
            if (Array.isArray(value)) {
              for (const item of value) {
                responseHeaders.append(name, item);
              }
            } else if (value !== undefined) {
              responseHeaders.set(name, String(value));
            }
          }
          resolve(new Response(Buffer.concat(chunks), {
            status: incoming.statusCode ?? 599,
            statusText: incoming.statusMessage,
            headers: responseHeaders,
          }));
        });
      });

      const cleanup = () => {
        options.signal.removeEventListener('abort', abort);
        request.removeListener('error', onError);
      };
      const onError = (error: Error) => {
        cleanup();
        reject(error);
      };
      const abort = () => {
        request.destroy(new Error('Request aborted'));
      };

      request.on('error', onError);
      if (options.signal.aborted) {
        abort();
        return;
      }
      options.signal.addEventListener('abort', abort, { once: true });
      request.end();
    });
  }

  private async lookupHostname(hostname: string): Promise<Array<{ address: string; family: number }>> {
    return lookup(hostname, { all: true, verbatim: true });
  }

  private normalizeHost(hostname: string): string {
    return hostname.replace(/^\[(.*)\]$/, '$1').replace(/\.$/, '').toLowerCase();
  }

  private isLocalHostname(hostname: string): boolean {
    return hostname === 'localhost' || hostname.endsWith('.localhost') || hostname.endsWith('.local');
  }

  private isPublicIpAddress(address: string): boolean {
    const normalized = this.normalizeHost(address);

    if (normalized.startsWith('::ffff:')) {
      const mappedIPv4 = normalized.substring('::ffff:'.length);
      if (isIP(mappedIPv4) === 4) {
        return this.isPublicIPv4(mappedIPv4);
      }
    }

    const family = isIP(normalized);
    if (family === 4) return this.isPublicIPv4(normalized);
    if (family === 6) return this.isPublicIPv6(normalized);
    return true;
  }

  private isPublicIPv4(address: string): boolean {
    const octets = address.split('.').map(Number);
    if (octets.length !== 4 || octets.some(part => !Number.isInteger(part) || part < 0 || part > 255)) {
      return false;
    }

    const [a, b, c] = octets;

    if (a === 0 || a === 10 || a === 127) return false;
    if (a === 100 && b >= 64 && b <= 127) return false; // RFC 6598 CGNAT
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 192 && b === 0) return false;
    if (a === 192 && b === 88 && c === 99) return false;
    if (a === 198 && (b === 18 || b === 19)) return false;
    if (a === 198 && b === 51 && c === 100) return false;
    if (a === 203 && b === 0 && c === 113) return false;
    if (a >= 224) return false; // Multicast + reserved

    return true;
  }

  private isPublicIPv6(address: string): boolean {
    const normalized = address.toLowerCase();

    if (normalized === '::' || normalized === '::1') return false;
    if (/^fe[89ab][0-9a-f]:/i.test(normalized)) return false; // fe80::/10
    if (/^f[cd][0-9a-f]{2}:/i.test(normalized)) return false; // fc00::/7
    if (/^ff[0-9a-f]{2}:/i.test(normalized)) return false; // ff00::/8
    if (normalized.startsWith('2001:db8:')) return false; // documentation range

    return true;
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

export default UrlScanAdapter;
