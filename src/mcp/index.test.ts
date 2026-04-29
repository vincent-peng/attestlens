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
    it('exposes explicit enrichment, typosquat, behavioral, iac, gitleaks, and timeout options on MCP scan tools', () => {
      const scanTool = MCP_TOOLS.find((tool) => tool.name === 'attestlens_scan');
      const auditTool = MCP_TOOLS.find((tool) => tool.name === 'attestlens_audit');
      const urlTool = MCP_TOOLS.find((tool) => tool.name === 'attestlens_scan_url');

      expect(scanTool?.inputSchema.properties).toHaveProperty('externalEnrichment');
      expect(auditTool?.inputSchema.properties).toHaveProperty('externalEnrichment');
      expect(urlTool?.inputSchema.properties).not.toHaveProperty('externalEnrichment');
      expect(scanTool?.inputSchema.properties).toHaveProperty('includeTyposquat');
      expect(auditTool?.inputSchema.properties).toHaveProperty('includeTyposquat');
      expect(urlTool?.inputSchema.properties).not.toHaveProperty('includeTyposquat');
      expect(scanTool?.inputSchema.properties).toHaveProperty('scannerTimeoutMs');
      expect(auditTool?.inputSchema.properties).toHaveProperty('scannerTimeoutMs');
      expect(urlTool?.inputSchema.properties).toHaveProperty('scannerTimeoutMs');
      expect(scanTool?.inputSchema.properties).toHaveProperty('behavioral');
      expect(auditTool?.inputSchema.properties).toHaveProperty('behavioral');
      expect(urlTool?.inputSchema.properties).not.toHaveProperty('behavioral');
      expect(scanTool?.inputSchema.properties).toHaveProperty('iac');
      expect(auditTool?.inputSchema.properties).toHaveProperty('iac');
      expect(urlTool?.inputSchema.properties).not.toHaveProperty('iac');
      expect(scanTool?.inputSchema.properties).toHaveProperty('includeGitleaks');
      expect(auditTool?.inputSchema.properties).toHaveProperty('includeGitleaks');
      expect(urlTool?.inputSchema.properties).not.toHaveProperty('includeGitleaks');
      expect(scanTool?.inputSchema.properties).toHaveProperty('gitleaksPath');
      expect(auditTool?.inputSchema.properties).toHaveProperty('gitleaksPath');
      expect(urlTool?.inputSchema.properties).not.toHaveProperty('gitleaksPath');
      expect((auditTool?.inputSchema.properties as any).format.enum).toContain('agent');
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

    it('returns agent audits as machine-readable JSON', async () => {
      vi.spyOn(ScannerOrchestrator.prototype, 'scan').mockResolvedValue({
        findings: [],
        results: [],
        errors: [],
        totalDurationMs: 10,
        ruleFreshness: makeRuleFreshness(),
      });

      const response = await handleToolCall('attestlens_audit', {
        path: tempDir,
        format: 'agent',
        opinion: true,
      });
      const payload = JSON.parse(response.content[0].text);

      expect(payload.schema).toBe('attestlens-agent-v1');
      expect(payload).toEqual(expect.objectContaining({
        verdict: expect.any(String),
        confidence: expect.any(String),
        score: expect.any(Number),
        actions: expect.any(Array),
      }));
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

    it('keeps MCP typosquat findings disabled by default', async () => {
      await writeMcpPackageProject(tempDir, 'lodas');

      const response = await handleToolCall('attestlens_scan', { path: tempDir });
      const payload = JSON.parse(response.content[0].text);

      expect(payload.findings.some((finding: { sourceRule: string }) => finding.sourceRule === 'VS-SC-004')).toBe(false);
      expect(payload.errors.some((error: { code?: string }) => error.code === 'EXPERIMENTAL_TYPOSQUAT')).toBe(false);
    });

    it('enables MCP typosquat findings only when explicitly requested', async () => {
      await writeMcpPackageProject(tempDir, 'lodas');

      const response = await handleToolCall('attestlens_scan', {
        path: tempDir,
        includeTyposquat: true,
      });
      const payload = JSON.parse(response.content[0].text);

      expect(payload.findings.some((finding: { sourceRule: string }) => finding.sourceRule === 'VS-SC-004')).toBe(true);
      expect(payload.errors.some((error: { code?: string }) => error.code === 'EXPERIMENTAL_TYPOSQUAT')).toBe(true);
    });

    it('rejects invalid MCP scanner timeout values', async () => {
      await expect(handleToolCall('attestlens_scan', {
        path: tempDir,
        scannerTimeoutMs: 0,
      })).rejects.toThrow('scannerTimeoutMs must be a positive integer');
    });

    it('enables MCP behavioral findings by default and allows explicit disable', async () => {
      await writeMcpBehavioralProject(tempDir);

      const enabledResponse = await handleToolCall('attestlens_scan', { path: tempDir });
      const enabledPayload = JSON.parse(enabledResponse.content[0].text);
      expect(enabledPayload.findings.some((finding: { sourceRule: string }) => finding.sourceRule === 'VS-BH-001')).toBe(true);

      const disabledResponse = await handleToolCall('attestlens_scan', { path: tempDir, behavioral: false });
      const disabledPayload = JSON.parse(disabledResponse.content[0].text);
      expect(disabledPayload.findings.some((finding: { sourceRule: string }) => finding.sourceRule === 'VS-BH-001')).toBe(false);
    });

    it('accepts MCP gitleaks opt-in and skips when the binary is unavailable', async () => {
      await writeMcpPackageProject(tempDir, 'gitleaks-target');
      await fs.mkdir(path.join(tempDir, '.git'), { recursive: true });

      const response = await handleToolCall('attestlens_scan', {
        path: tempDir,
        includeGitleaks: true,
        gitleaksPath: '/definitely/not/gitleaks',
      });
      const payload = JSON.parse(response.content[0].text);

      expect(payload.errors.some((error: { source: string; code?: string }) => (
        error.source === 'gitleaks' && error.code === 'SCANNER_UNAVAILABLE'
      ))).toBe(true);
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

async function writeMcpBehavioralProject(projectDir: string): Promise<void> {
  await fs.writeFile(path.join(projectDir, 'package.json'), JSON.stringify({
    name: 'mcp-behavioral-project',
    version: '1.0.0',
    dependencies: { 'behavior-pkg': '1.0.0' },
  }, null, 2));
  await fs.mkdir(path.join(projectDir, 'node_modules', 'behavior-pkg'), { recursive: true });
  await fs.writeFile(path.join(projectDir, 'node_modules', 'behavior-pkg', 'package.json'), JSON.stringify({
    name: 'behavior-pkg',
    version: '1.0.0',
  }, null, 2));
  await fs.writeFile(path.join(projectDir, 'node_modules', 'behavior-pkg', 'index.js'), 'export const run = (code) => eval(code);');
}
