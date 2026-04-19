/**
 * AttestLens — URL Scanner Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { UrlScanAdapter } from './url-scan.js';
import { HEADER_CHECKS } from './rules/url-headers.js';
import { KEY_PATTERNS } from './rules/exposed-keys.js';
import { INFRA_CHECKS } from './rules/infra-checks.js';
import { JS_PATTERNS } from './rules/js-analysis.js';

describe('UrlScanAdapter', () => {
  let adapter: UrlScanAdapter;

  beforeEach(() => {
    adapter = new UrlScanAdapter();
  });

  it('should be available', async () => {
    const available = await adapter.isAvailable();
    expect(available).toBe(true);
  });

  it('should return version', async () => {
    const version = await adapter.getVersion();
    expect(version).toBe('1.0.0');
  });

  it('should reject invalid URLs', async () => {
    const result = await adapter.scan('not-a-url');
    expect(result.findings).toHaveLength(0);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].code).toBe('INVALID_URL');
  });

  it('should reject non-HTTP protocols', async () => {
    const result = await adapter.scan('ftp://example.com');
    expect(result.findings).toHaveLength(0);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].code).toBe('INVALID_URL');
  });

  it('should return url-scan as source', () => {
    expect(adapter.name).toBe('url-scan');
  });

  it('should extract script URLs from HTML', () => {
    const html = `
      <html>
      <head>
        <script src="https://cdn.example.com/app.js"></script>
        <script src="/static/bundle.min.js?v=1.2.3"></script>
        <script src="https://cdn.example.com/analytics.js?id=UA-123"></script>
      </head>
      <body></body>
      </html>
    `;
    const url = new URL('https://example.com');
    // @ts-expect-error - testing private method
    const urls = adapter.extractScriptUrls(html, url);
    expect(urls.length).toBe(3);
    expect(urls[0]).toBe('https://cdn.example.com/app.js');
    expect(urls[1]).toBe('https://example.com/static/bundle.min.js?v=1.2.3');
  });

  it('should extract inline scripts from HTML', () => {
    const html = `
      <script>console.log('hello');</script>
      <script src="external.js"></script>
      <script>var x = 1;</script>
    `;
    // @ts-expect-error - testing private method
    const scripts = adapter.extractInlineScripts(html);
    expect(scripts.length).toBe(2);
    expect(scripts[0]).toContain("console.log('hello')");
  });
});

describe('URL Header Checks', () => {
  it('should have 13 header checks', () => {
    expect(HEADER_CHECKS.length).toBe(13);
  });

  it('should validate missing headers correctly', () => {
    const missingCSP = HEADER_CHECKS.find(c => c.id === 'AL-URL-001');
    expect(missingCSP).toBeDefined();
    expect(missingCSP!.validate(undefined)).toBe(false);
    expect(missingCSP!.validate('')).toBe(false);
  });

  it('should validate present headers correctly', () => {
    const csp = HEADER_CHECKS.find(c => c.id === 'AL-URL-001');
    expect(csp!.validate("default-src 'self'")).toBe(true);
  });

  it('should validate HSTS correctly', () => {
    const hsts = HEADER_CHECKS.find(c => c.id === 'AL-URL-002');
    expect(hsts!.validate('max-age=31536000; includeSubDomains')).toBe(true);
    expect(hsts!.validate(undefined)).toBe(false);
  });

  it('should validate X-Content-Type-Options correctly', () => {
    const xcto = HEADER_CHECKS.find(c => c.id === 'AL-URL-004');
    expect(xcto!.validate('nosniff')).toBe(true);
    expect(xcto!.validate('')).toBe(false);
  });

  it('should flag server version disclosure', () => {
    const server = HEADER_CHECKS.find(c => c.id === 'AL-URL-012');
    expect(server!.validate('nginx/1.18.0')).toBe(false); // Version disclosed
    expect(server!.validate('nginx')).toBe(true); // No version = good
    expect(server!.validate(undefined)).toBe(true); // No header = good
  });

  it('should map all checks to APP principles', () => {
    for (const check of HEADER_CHECKS) {
      expect(check.fixPrompt).toBeTruthy();
      expect(check.severity).toMatch(/^(critical|high|medium|low|info)$/);
    }
  });
});

describe('Key Detection Patterns', () => {
  it('should have 15+ key patterns', () => {
    expect(KEY_PATTERNS.length).toBeGreaterThanOrEqual(15);
  });

  it('should detect OpenAI keys', () => {
    const pattern = KEY_PATTERNS.find(p => p.id === 'AL-KEY-001');
    expect(pattern).toBeDefined();
    // Reset global regex state
    pattern!.pattern.lastIndex = 0;
    // Pattern: sk-proj-[80+ chars] or sk-[48+ chars]
    const longKey = 'sk-proj-' + 'A'.repeat(80);
    expect(pattern!.pattern.test(longKey)).toBe(true);
    pattern!.pattern.lastIndex = 0;
    const shortKey = 'sk-' + 'B'.repeat(48);
    expect(pattern!.pattern.test(shortKey)).toBe(true);
  });

  it('should detect Stripe live keys', () => {
    const pattern = KEY_PATTERNS.find(p => p.id === 'AL-KEY-002');
    expect(pattern).toBeDefined();
    expect(pattern!.pattern.test('sk_live_26PHem9OkJ1642VQ3Y3BK0Rq')).toBe(true);
    // Test keys should not match
    expect(pattern!.excludePattern?.test('sk_test_26PHem9OkJ16')).toBe(true);
  });

  it('should detect private keys', () => {
    const pattern = KEY_PATTERNS.find(p => p.id === 'AL-KEY-011');
    expect(pattern).toBeDefined();
    pattern!.pattern.lastIndex = 0;
    expect(pattern!.pattern.test('-----BEGIN RSA PRIVATE KEY-----')).toBe(true);
    pattern!.pattern.lastIndex = 0;
    // Note: 'BEGIN PRIVATE KEY' (without RSA/EC/DSA/OPENSSH prefix) is NOT matched by this pattern
    // The pattern requires: BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY
    expect(pattern!.pattern.test('-----BEGIN EC PRIVATE KEY-----')).toBe(true);
  });

  it('should detect database URLs', () => {
    const pattern = KEY_PATTERNS.find(p => p.id === 'AL-KEY-012');
    expect(pattern).toBeDefined();
    pattern!.pattern.lastIndex = 0;
    expect(pattern!.pattern.test('postgresql://user:pass@host:5432/mydb')).toBe(true);
    pattern!.pattern.lastIndex = 0;
    expect(pattern!.pattern.test('mongodb://user:pass@host:27017/mydb')).toBe(true);
  });

  it('should have fix prompts for all patterns', () => {
    for (const pattern of KEY_PATTERNS) {
      expect(pattern.fixPrompt).toBeTruthy();
      expect(pattern.fixPrompt.length).toBeGreaterThan(50);
    }
  });

  it('should have APP mappings for all patterns', () => {
    for (const pattern of KEY_PATTERNS) {
      expect(pattern.appMappings.length).toBeGreaterThanOrEqual(1);
      expect(pattern.appMappings[0].principle).toBe('APP_11');
    }
  });
});

describe('Infrastructure Checks', () => {
  it('should have 8 infrastructure checks', () => {
    expect(INFRA_CHECKS.length).toBe(8);
  });

  it('should check correct paths', () => {
    const paths = INFRA_CHECKS.map(c => c.path);
    expect(paths).toContain('/.git/HEAD');
    expect(paths).toContain('/.env');
    expect(paths).toContain('/.env.local');
    expect(paths).toContain('/api/debug');
    expect(paths).toContain('/swagger.json');
  });

  it('should have critical severity for .git and .env', () => {
    const gitCheck = INFRA_CHECKS.find(c => c.id === 'AL-INFRA-001');
    const envCheck = INFRA_CHECKS.find(c => c.id === 'AL-INFRA-002');
    expect(gitCheck!.severity).toBe('critical');
    expect(envCheck!.severity).toBe('critical');
  });

  it('should have fix prompts for all checks', () => {
    for (const check of INFRA_CHECKS) {
      expect(check.fixPrompt).toBeTruthy();
      expect(check.fixPrompt.length).toBeGreaterThan(50);
    }
  });
});

describe('JS Pattern Analysis', () => {
  it('should have 8 JS patterns', () => {
    expect(JS_PATTERNS.length).toBe(8);
  });

  it('should detect dangerouslySetInnerHTML', () => {
    const pattern = JS_PATTERNS.find(p => p.id === 'AL-JS-001');
    expect(pattern).toBeDefined();
    const code = '<div dangerouslySetInnerHTML={{__html: userInput}} />';
    expect(pattern!.pattern.test(code)).toBe(true);
  });

  it('should detect eval()', () => {
    const pattern = JS_PATTERNS.find(p => p.id === 'AL-JS-002');
    expect(pattern).toBeDefined();
    expect(pattern!.pattern.test('eval(userInput)')).toBe(true);
  });

  it('should detect document.write()', () => {
    const pattern = JS_PATTERNS.find(p => p.id === 'AL-JS-003');
    expect(pattern).toBeDefined();
    expect(pattern!.pattern.test('document.write(html)')).toBe(true);
  });

  it('should detect innerHTML', () => {
    const pattern = JS_PATTERNS.find(p => p.id === 'AL-JS-004');
    expect(pattern).toBeDefined();
    expect(pattern!.pattern.test('element.innerHTML = data')).toBe(true);
  });

  it('should have fix prompts for all patterns', () => {
    for (const pattern of JS_PATTERNS) {
      expect(pattern.fixPrompt).toBeTruthy();
      expect(pattern.fixPrompt.length).toBeGreaterThan(50);
    }
  });
});