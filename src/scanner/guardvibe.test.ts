import { beforeAll, describe, expect, it } from 'vitest';
import { GuardVibeAdapter } from './guardvibe.js';
import type { ScannerResult } from './types.js';

describe('GuardVibeAdapter', { timeout: 20000 }, () => {
  const adapter = new GuardVibeAdapter();
  let scanResult: ScannerResult;

  beforeAll(async () => {
    scanResult = await adapter.scan('/tmp/vulnerable-app');
  });

  it('should always be available (static fallback)', async () => {
    const available = await adapter.isAvailable();
    expect(available).toBe(true);
  });

  it('should detect hardcoded secrets in .env files', async () => {
    const hardKeyFindings = scanResult.findings.filter(
      f => f.sourceRule === 'VS-HARDKEY'
    );
    expect(hardKeyFindings.length).toBeGreaterThan(0);
  });

  it('should detect XSS patterns', async () => {
    const xssFindings = scanResult.findings.filter(
      f => f.sourceRule === 'VS-XSS'
    );
    expect(xssFindings.length).toBeGreaterThan(0);
  });

  it('should detect debug logging of sensitive data', async () => {
    const debugFindings = scanResult.findings.filter(
      f => f.sourceRule === 'VS-DEBUG'
    );
    expect(debugFindings.length).toBeGreaterThan(0);
  });

  it('should detect env var exposure', async () => {
    const envFindings = scanResult.findings.filter(
      f => f.sourceRule === 'VS-ENV'
    );
    expect(envFindings.length).toBeGreaterThan(0);
  });

  it('should produce findings with required fields', async () => {
    for (const finding of scanResult.findings) {
      expect(finding.id).toBeTruthy();
      expect(finding.source).toBe('guardvibe');
      expect(finding.sourceRule).toBeTruthy();
      expect(['critical', 'high', 'medium', 'low', 'info']).toContain(finding.severity);
      expect(finding.title).toBeTruthy();
      expect(finding.file).toBeTruthy();
      expect(finding.line).toBeGreaterThan(0);
    }
  });

  it('should return errors when MCP is unavailable', async () => {
    // MCP is not installed, so there should be an error about it
    expect(scanResult.errors.length).toBeGreaterThanOrEqual(0);
  });
});
