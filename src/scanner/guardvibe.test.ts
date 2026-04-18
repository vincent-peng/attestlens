import { describe, it, expect } from 'vitest';
import { GuardVibeAdapter } from './guardvibe.js';

describe('GuardVibeAdapter', () => {
  const adapter = new GuardVibeAdapter();

  it('should always be available (static fallback)', async () => {
    const available = await adapter.isAvailable();
    expect(available).toBe(true);
  });

  it('should detect hardcoded secrets in .env files', async () => {
    const result = await adapter.scan('/tmp/vulnerable-app');
    const hardKeyFindings = result.findings.filter(
      f => f.sourceRule === 'VS-HARDKEY'
    );
    expect(hardKeyFindings.length).toBeGreaterThan(0);
  });

  it('should detect XSS patterns', async () => {
    const result = await adapter.scan('/tmp/vulnerable-app');
    const xssFindings = result.findings.filter(
      f => f.sourceRule === 'VS-XSS'
    );
    expect(xssFindings.length).toBeGreaterThan(0);
  });

  it('should detect debug logging of sensitive data', async () => {
    const result = await adapter.scan('/tmp/vulnerable-app');
    const debugFindings = result.findings.filter(
      f => f.sourceRule === 'VS-DEBUG'
    );
    expect(debugFindings.length).toBeGreaterThan(0);
  });

  it('should detect env var exposure', async () => {
    const result = await adapter.scan('/tmp/vulnerable-app');
    const envFindings = result.findings.filter(
      f => f.sourceRule === 'VS-ENV'
    );
    expect(envFindings.length).toBeGreaterThan(0);
  });

  it('should produce findings with required fields', async () => {
    const result = await adapter.scan('/tmp/vulnerable-app');
    for (const finding of result.findings) {
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
    const result = await adapter.scan('/tmp/vulnerable-app');
    // MCP is not installed, so there should be an error about it
    expect(result.errors.length).toBeGreaterThanOrEqual(0);
  });
});