/**
 * AttestLens — URL Scanner Tests
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { UrlScanAdapter } from './url-scan.js';
import { HEADER_CHECKS } from './rules/url-headers.js';
import { KEY_PATTERNS } from './rules/exposed-keys.js';
import { INFRA_CHECKS } from './rules/infra-checks.js';
import { JS_PATTERNS } from './rules/js-analysis.js';

function response(body: string, init: ResponseInit = {}): Response {
  return new Response(body, init);
}

function stubPublicLookup(adapter: UrlScanAdapter, hosts: Record<string, string> = {}) {
  return vi.spyOn(adapter as any, 'lookupHostname').mockImplementation(async (...args: any[]) => {
    const hostname = args[0] as string;
    const address = hosts[hostname] ?? '93.184.216.34';
    return [{ address, family: address.includes(':') ? 6 : 4 }];
  });
}

function stubSlowPaths(adapter: UrlScanAdapter) {
  vi.spyOn(adapter as any, 'probeInfra').mockResolvedValue(undefined);
  vi.spyOn(adapter as any, 'sleep').mockResolvedValue(undefined);
  vi.spyOn(adapter as any, 'checkSSL').mockReturnValue([]);
}

describe('UrlScanAdapter', () => {
  let adapter: UrlScanAdapter;

  beforeEach(() => {
    adapter = new UrlScanAdapter();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
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

  it('should reject localhost targets', async () => {
    const result = await adapter.scan('http://localhost');
    expect(result.findings).toHaveLength(0);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].code).toBe('INVALID_URL');
  });

  it('should reject loopback IPv4 targets', async () => {
    const result = await adapter.scan('http://127.0.0.1');
    expect(result.findings).toHaveLength(0);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].code).toBe('INVALID_URL');
  });

  it('should reject loopback IPv6 targets', async () => {
    const result = await adapter.scan('http://[::1]');
    expect(result.findings).toHaveLength(0);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].code).toBe('INVALID_URL');
  });

  it('should reject hosts that resolve to private IPs', async () => {
    vi.spyOn(adapter as any, 'lookupHostname').mockResolvedValue([{ address: '10.0.0.5', family: 4 }]);
    await expect((adapter as any).assertPublicScanTarget(new URL('https://example.com'))).rejects.toThrow(/private\/internal IP/i);
  });

  it('should allow hosts that resolve to public IPs', async () => {
    vi.spyOn(adapter as any, 'lookupHostname').mockResolvedValue([{ address: '93.184.216.34', family: 4 }]);
    await expect((adapter as any).assertPublicScanTarget(new URL('https://example.com'))).resolves.toBeUndefined();
  });

  it('should reject redirects to private targets', async () => {
    stubPublicLookup(adapter);
    const fetchMock = vi.fn().mockResolvedValue(
      response('', {
        status: 302,
        headers: { location: 'http://127.0.0.1/internal' },
      }),
    );
    vi.stubGlobal('fetch', fetchMock);

    const result = await adapter.scan('https://example.com');

    expect(result.findings).toHaveLength(0);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].code).toBe('INVALID_URL');
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('should skip blocked script URLs without failing the scan', async () => {
    stubPublicLookup(adapter);
    stubSlowPaths(adapter);
    vi.spyOn(adapter as any, 'checkSourceMaps').mockResolvedValue([]);

    const fetchMock = vi.fn().mockImplementation(async (url: string) => {
      if (url === 'https://example.com/') {
        return response('<script src="http://localhost/app.js"></script>', { status: 200 });
      }
      return response('', { status: 404 });
    });
    vi.stubGlobal('fetch', fetchMock);

    const result = await adapter.scan('https://example.com');

    expect(result.errors).toHaveLength(0);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('should skip blocked source map URLs without fetching them', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    const findings = await (adapter as any).checkSourceMaps(['http://localhost/app.js']);

    expect(findings).toHaveLength(0);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('should stop fetching later bundles once the JS budget is exhausted', async () => {
    stubPublicLookup(adapter, { 'cdn.example.com': '93.184.216.34' });
    const fetchMock = vi.fn().mockImplementation(async (url: string) => {
      if (url === 'https://cdn.example.com/first.js') {
        return response('first');
      }
      if (url === 'https://cdn.example.com/second.js') {
        return response('second-bundle');
      }
      if (url === 'https://cdn.example.com/third.js') {
        return response('third');
      }
      throw new Error(`Unexpected fetch: ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    const results = await (adapter as any).fetchJavaScriptBundles([
      'https://cdn.example.com/first.js',
      'https://cdn.example.com/second.js',
      'https://cdn.example.com/third.js',
    ], 8);

    expect(Array.from(results.keys())).toEqual(['https://cdn.example.com/first.js']);
    expect(fetchMock.mock.calls.map(call => call[0])).toEqual([
      'https://cdn.example.com/first.js',
      'https://cdn.example.com/second.js',
    ]);
  });

  it('should preserve script order for stored JS bundles', async () => {
    stubPublicLookup(adapter, { 'cdn.example.com': '93.184.216.34' });
    const fetchMock = vi.fn().mockImplementation(async (url: string) => {
      if (url === 'https://cdn.example.com/one.js') return response('one');
      if (url === 'https://cdn.example.com/two.js') return response('two');
      if (url === 'https://cdn.example.com/three.js') return response('three');
      throw new Error(`Unexpected fetch: ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    const results = await (adapter as any).fetchJavaScriptBundles([
      'https://cdn.example.com/one.js',
      'https://cdn.example.com/two.js',
      'https://cdn.example.com/three.js',
    ], 64);

    expect(Array.from(results.keys())).toEqual([
      'https://cdn.example.com/one.js',
      'https://cdn.example.com/two.js',
      'https://cdn.example.com/three.js',
    ]);
  });

  it('should not retain partially downloaded oversized bundles', async () => {
    stubPublicLookup(adapter, { 'cdn.example.com': '93.184.216.34' });
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response('oversized')));

    const results = await (adapter as any).fetchJavaScriptBundles([
      'https://cdn.example.com/big.js',
    ], 5);

    expect(results.size).toBe(0);
  });

  it('should probe source maps with .map before the query string', async () => {
    stubPublicLookup(adapter, { 'cdn.example.com': '93.184.216.34' });
    const fetchMock = vi.fn().mockResolvedValue(response('{}', { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);

    const findings = await (adapter as any).checkSourceMaps([
      'https://cdn.example.com/app.js?v=1.2.3',
    ]);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe('https://cdn.example.com/app.js.map?v=1.2.3');
    expect(findings.some((finding: any) => finding.sourceRule === 'AL-JS-007')).toBe(true);
  });

  it('should resolve relative scripts against the final redirected page URL', async () => {
    stubPublicLookup(adapter, {
      'example.com': '93.184.216.34',
      'www.example.com': '93.184.216.34',
    });
    stubSlowPaths(adapter);
    vi.spyOn(adapter as any, 'checkSourceMaps').mockResolvedValue([]);

    const fetchMock = vi.fn().mockImplementation(async (url: string) => {
      if (url === 'https://example.com/') {
        return response('', {
          status: 302,
          headers: { location: 'https://www.example.com/app/' },
        });
      }
      if (url === 'https://www.example.com/app/') {
        return response('<script src="./bundle.js?v=1"></script>', {
          status: 200,
          headers: { 'content-security-policy': "default-src 'self'" },
        });
      }
      if (url === 'https://www.example.com/app/bundle.js?v=1') {
        return response('eval(userInput)', { status: 200 });
      }
      throw new Error(`Unexpected fetch: ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    const result = await adapter.scan('https://example.com');

    expect(fetchMock.mock.calls.map(call => call[0])).toContain('https://www.example.com/app/bundle.js?v=1');
    expect(result.findings.some(finding => finding.sourceRule === 'AL-JS-002')).toBe(true);
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
  let adapter: UrlScanAdapter;

  beforeEach(() => {
    adapter = new UrlScanAdapter();
  });

  it('should have 12 header checks', () => {
    expect(HEADER_CHECKS.length).toBe(12);
  });

  it('should not include the duplicate Cache-Control rule', () => {
    expect(HEADER_CHECKS.find(c => c.id === 'AL-URL-016')).toBeUndefined();
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

  it('should emit a single Cache-Control finding when the header is missing', () => {
    const findings = (adapter as any).checkHeaders(new Headers(), 'https://example.com');
    const cacheControlFindings = findings.filter((finding: any) =>
      finding.sourceRule === 'AL-URL-011' || finding.sourceRule === 'AL-URL-016',
    );

    expect(cacheControlFindings).toHaveLength(1);
    expect(cacheControlFindings[0].sourceRule).toBe('AL-URL-011');
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
    pattern!.pattern.lastIndex = 0;
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
    expect(pattern!.excludePattern?.test('sk_test_26PHem9OkJ16')).toBe(true);
  });

  it('should detect private keys', () => {
    const pattern = KEY_PATTERNS.find(p => p.id === 'AL-KEY-011');
    expect(pattern).toBeDefined();
    pattern!.pattern.lastIndex = 0;
    expect(pattern!.pattern.test('-----BEGIN RSA PRIVATE KEY-----')).toBe(true);
    pattern!.pattern.lastIndex = 0;
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
    pattern!.pattern.lastIndex = 0;
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
