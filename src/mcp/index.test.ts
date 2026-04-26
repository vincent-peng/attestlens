import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { McpError } from '@modelcontextprotocol/sdk/types.js';

import { ScannerOrchestrator } from '../scanner/orchestrator.js';
import { MCP_TOOLS, handleToolCall, validatePath, validateUrl } from './index.js';

function makeRuleFreshness() {
  return {
    version: '2026.04.24',
    generated: '2026-04-24T00:00:00.000Z',
    loadedAt: '2026-04-24T00:00:00.000Z',
    source: 'embedded' as const,
    ruleCount: 42,
    ageDays: 0,
    stale: false,
    cachePath: '/Users/alice/.attestlens/rules/latest.json',
  };
}

describe('MCP Server', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-mcp-'));
    delete process.env.ATTESTLENS_ALLOWED_ROOTS;
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    delete process.env.ATTESTLENS_ALLOWED_ROOTS;
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  describe('validatePath', () => {
    it('allows valid directories when ATTESTLENS_ALLOWED_ROOTS is not set', async () => {
      await expect(validatePath(tempDir)).resolves.toBe(tempDir);
    });

    it('blocks paths outside allowed roots', async () => {
      process.env.ATTESTLENS_ALLOWED_ROOTS = tempDir;

      await expect(validatePath('/etc')).rejects.toThrow(McpError);
    });

    it('rejects shell metacharacters', async () => {
      await expect(validatePath(`${tempDir};rm -rf /`)).rejects.toThrow('path contains invalid characters');
    });
  });

  describe('validateUrl', () => {
    it('accepts public http(s) URLs', () => {
      expect(validateUrl('https://example.com')).toBe('https://example.com/');
      expect(validateUrl('http://example.com/path')).toBe('http://example.com/path');
    });

    it('rejects non-http protocols', () => {
      expect(() => validateUrl('file:///tmp/report')).toThrow('unsupported URL protocol');
    });

    it('rejects invalid URLs', () => {
      expect(() => validateUrl('not-a-url')).toThrow('invalid URL');
    });
  });

  describe('handleToolCall', () => {
    it('exposes external enrichment only for MCP path scan and audit tools', () => {
      const scanTool = MCP_TOOLS.find((tool) => tool.name === 'attestlens_scan');
      const auditTool = MCP_TOOLS.find((tool) => tool.name === 'attestlens_audit');
      const urlTool = MCP_TOOLS.find((tool) => tool.name === 'attestlens_scan_url');

      expect(scanTool?.inputSchema.properties).toHaveProperty('externalEnrichment');
      expect(auditTool?.inputSchema.properties).toHaveProperty('externalEnrichment');
      expect(urlTool?.inputSchema.properties).not.toHaveProperty('externalEnrichment');
    });

    it('returns URL scan output keyed by targetUrl', async () => {
      const scanSpy = vi.spyOn(ScannerOrchestrator.prototype, 'scan').mockResolvedValue({
        findings: [
          {
            id: 'FIND-001',
            source: 'url-scan',
            sourceRule: 'AL-URL-001',
            severity: 'high',
            category: 'Security Headers',
            title: 'Missing CSP header',
            description: 'Content-Security-Policy header is missing',
            url: 'https://example.com',
            appMappings: [],
            evidence: {
              timestamp: new Date().toISOString(),
              scannerVersion: '0.1.0',
              rawOutput: {},
            },
          },
        ],
        results: [
          {
            source: 'url-scan',
            version: '1.0.0',
            timestamp: new Date().toISOString(),
            findings: [
              {
                id: 'FIND-001',
                source: 'url-scan',
                sourceRule: 'AL-URL-001',
                severity: 'high',
                category: 'Security Headers',
                title: 'Missing CSP header',
                description: 'Content-Security-Policy header is missing',
                url: 'https://example.com',
                appMappings: [],
                evidence: {
                  timestamp: new Date().toISOString(),
                  scannerVersion: '0.1.0',
                  rawOutput: {},
                },
              },
            ],
            errors: [],
            durationMs: 42,
          },
        ],
        errors: [],
        totalDurationMs: 42,
        ruleFreshness: makeRuleFreshness(),
      });
      const disableSpy = vi.spyOn(ScannerOrchestrator.prototype, 'disable');

      const response = await handleToolCall('attestlens_scan_url', {
        url: 'https://user:pass@example.com/path?token=abc#frag',
        strict: true,
      });
      const payload = JSON.parse(response.content[0].text);

      expect(payload.targetType).toBe('url');
      expect(payload.targetUrl).toBe('https://example.com/path');
      expect(payload.summary.total).toBe(1);
      expect(payload.findings[0].sourceRule).toBe('AL-URL-001');
      expect(payload.ruleFreshness.cachePath).toBeUndefined();
      expect(JSON.stringify(payload)).not.toContain('/Users/alice');
      expect(scanSpy).toHaveBeenCalledWith('https://user:pass@example.com/path?token=abc#frag');
      expect(disableSpy).toHaveBeenCalledWith('guardvibe');
      expect(disableSpy).toHaveBeenCalledWith('mcp-scan');
      expect(disableSpy).toHaveBeenCalledWith('supply-chain');
    });

    it('rejects blocked URL scan requests instead of returning a clean payload', async () => {
      vi.spyOn(ScannerOrchestrator.prototype, 'scan').mockResolvedValue({
        findings: [],
        results: [
          {
            source: 'url-scan',
            version: '1.0.0',
            timestamp: new Date().toISOString(),
            findings: [],
            errors: [
              {
                source: 'url-scan',
                message: 'Invalid URL: Target resolves to a private/internal host: localhost. SSRF protection.',
                code: 'INVALID_URL',
                recoverable: false,
              },
            ],
            durationMs: 5,
          },
        ],
        errors: [
          {
            source: 'url-scan',
            message: 'Invalid URL: Target resolves to a private/internal host: localhost. SSRF protection.',
            code: 'INVALID_URL',
            recoverable: false,
          },
        ],
        totalDurationMs: 5,
        ruleFreshness: makeRuleFreshness(),
      });

      await expect(handleToolCall('attestlens_scan_url', {
        url: 'http://localhost:3000',
      })).rejects.toThrow('URL target is not allowed for scanning.');
    });

    it('returns PDF audits as base64-encoded payloads', async () => {
      vi.spyOn(ScannerOrchestrator.prototype, 'scan').mockResolvedValue({
        findings: [],
        results: [],
        errors: [],
        totalDurationMs: 10,
        ruleFreshness: makeRuleFreshness(),
      });

      const response = await handleToolCall('attestlens_audit', {
        path: tempDir,
        format: 'pdf',
      });
      const payload = JSON.parse(response.content[0].text);

      expect(payload.format).toBe('pdf');
      expect(payload.encoding).toBe('base64');
      expect(typeof payload.content).toBe('string');
      expect(Buffer.from(payload.content, 'base64').subarray(0, 4).toString()).toBe('%PDF');
    });

    it('strips cache paths from JSON audit report metadata', async () => {
      vi.spyOn(ScannerOrchestrator.prototype, 'scan').mockResolvedValue({
        findings: [],
        results: [],
        errors: [],
        totalDurationMs: 10,
        ruleFreshness: makeRuleFreshness(),
      });

      const response = await handleToolCall('attestlens_audit', {
        path: tempDir,
        format: 'json',
      });
      const payload = JSON.parse(response.content[0].text);

      expect(payload.metadata.ruleFreshness.cachePath).toBeUndefined();
      expect(response.content[0].text).not.toContain('/Users/alice');
    });

    it('keeps MCP scan external enrichment disabled by default', async () => {
      await writeMcpPackageProject(tempDir, 'external-only');
      const fetchMock = vi.fn(async () => {
        throw new Error('external enrichment should be disabled');
      });
      vi.stubGlobal('fetch', fetchMock);

      const response = await handleToolCall('attestlens_scan', { path: tempDir });
      const payload = JSON.parse(response.content[0].text);

      expect(payload.targetType).toBe('path');
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it('enables MCP scan external enrichment only when explicitly requested', async () => {
      await writeMcpPackageProject(tempDir, 'external-only');
      const fetchMock = vi.fn(async (input: string | URL) => {
        const url = String(input);
        if (url === 'https://registry.npmjs.org/external-only') {
          return new Response(JSON.stringify({
            name: 'external-only',
            version: '1.0.0',
            repository: { type: 'git', url: 'https://github.com/example/external-only.git' },
          }), { status: 200, headers: { 'content-type': 'application/json' } });
        }
        if (url === 'https://api.osv.dev/v1/querybatch') {
          return new Response(JSON.stringify({ results: [{}] }), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          });
        }
        return new Response('{}', { status: 404 });
      });
      vi.stubGlobal('fetch', fetchMock);

      const response = await handleToolCall('attestlens_scan', {
        path: tempDir,
        externalEnrichment: true,
      });
      const payload = JSON.parse(response.content[0].text);

      expect(payload.targetType).toBe('path');
      expect(fetchMock).toHaveBeenCalledWith(
        'https://registry.npmjs.org/external-only/1.0.0',
        expect.objectContaining({ method: 'GET' }),
      );
      expect(fetchMock).toHaveBeenCalledWith(
        'https://api.osv.dev/v1/querybatch',
        expect.objectContaining({ method: 'POST' }),
      );
    });

    it('enables MCP audit external enrichment only when explicitly requested', async () => {
      await writeMcpPackageProject(tempDir, 'external-audit');
      const fetchMock = vi.fn(async (input: string | URL) => {
        const url = String(input);
        if (url === 'https://registry.npmjs.org/external-audit') {
          return new Response(JSON.stringify({
            name: 'external-audit',
            version: '1.0.0',
            repository: { type: 'git', url: 'https://github.com/example/external-audit.git' },
          }), { status: 200, headers: { 'content-type': 'application/json' } });
        }
        if (url === 'https://api.osv.dev/v1/querybatch') {
          return new Response(JSON.stringify({ results: [{}] }), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          });
        }
        return new Response('{}', { status: 404 });
      });
      vi.stubGlobal('fetch', fetchMock);

      const response = await handleToolCall('attestlens_audit', {
        path: tempDir,
        format: 'json',
        externalEnrichment: true,
      });

      expect(() => JSON.parse(response.content[0].text)).not.toThrow();
      expect(fetchMock).toHaveBeenCalledWith(
        'https://registry.npmjs.org/external-audit/1.0.0',
        expect.objectContaining({ method: 'GET' }),
      );
      expect(fetchMock).toHaveBeenCalledWith(
        'https://api.osv.dev/v1/querybatch',
        expect.objectContaining({ method: 'POST' }),
      );
    });
  });
});

async function writeMcpPackageProject(projectDir: string, dependencyName: string): Promise<void> {
  await fs.writeFile(path.join(projectDir, 'package.json'), JSON.stringify({
    name: 'mcp-project',
    version: '1.0.0',
    dependencies: { [dependencyName]: '1.0.0' },
  }, null, 2));
}
