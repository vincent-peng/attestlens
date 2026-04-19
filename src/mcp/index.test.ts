import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { McpError } from '@modelcontextprotocol/sdk/types.js';

import { ScannerOrchestrator } from '../scanner/orchestrator.js';
import { handleToolCall, validatePath, validateUrl } from './index.js';

describe('MCP Server', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-mcp-'));
    delete process.env.ATTESTLENS_ALLOWED_ROOTS;
  });

  afterEach(async () => {
    vi.restoreAllMocks();
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
        results: [],
        errors: [],
        totalDurationMs: 42,
      });
      const disableSpy = vi.spyOn(ScannerOrchestrator.prototype, 'disable');

      const response = await handleToolCall('attestlens_scan_url', {
        url: 'https://example.com',
        strict: true,
      });
      const payload = JSON.parse(response.content[0].text);

      expect(payload.targetType).toBe('url');
      expect(payload.targetUrl).toBe('https://example.com/');
      expect(payload.summary.total).toBe(1);
      expect(payload.findings[0].sourceRule).toBe('AL-URL-001');
      expect(scanSpy).toHaveBeenCalledWith('https://example.com/');
      expect(disableSpy).toHaveBeenCalledWith('guardvibe');
      expect(disableSpy).toHaveBeenCalledWith('mcp-scan');
      expect(disableSpy).toHaveBeenCalledWith('supply-chain');
    });

    it('returns PDF audits as base64-encoded payloads', async () => {
      vi.spyOn(ScannerOrchestrator.prototype, 'scan').mockResolvedValue({
        findings: [],
        results: [],
        errors: [],
        totalDurationMs: 10,
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
  });
});
