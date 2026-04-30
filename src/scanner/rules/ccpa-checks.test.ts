import { describe, expect, it } from 'vitest';

import { CCPA_CHECKS, scanCcpaChecks } from './ccpa-checks.js';

describe('CCPA_CHECKS', () => {
  it('defines the requested CCPA scanner rules', () => {
    expect(CCPA_CHECKS.map((rule) => rule.id)).toEqual([
      'CCPA-DNS-001',
      'CCPA-DNS-002',
      'CCPA-PP-001',
      'CCPA-PP-002',
      'CCPA-GPC-001',
      'CCPA-SEC-001',
    ]);
  });

  it('detects missing Do Not Sell link with negative detection', () => {
    const findings = scanCcpaChecks([
      { relativePath: 'src/App.tsx', content: '<a href="/privacy">Privacy Policy</a>' },
    ], 'test');

    expect(findings.some((finding) => finding.sourceRule === 'CCPA-DNS-001')).toBe(true);
  });

  it('does not flag Do Not Sell when link text exists', () => {
    const findings = scanCcpaChecks([
      { relativePath: 'src/App.tsx', content: '<a>Do Not Sell or Share My Personal Information</a>' },
    ], 'test');

    expect(findings.some((finding) => finding.sourceRule === 'CCPA-DNS-001')).toBe(false);
  });

  it('detects missing Limit Sensitive PI link with negative detection', () => {
    const findings = scanCcpaChecks([
      { relativePath: 'index.html', content: '<a>Do Not Sell or Share My Personal Information</a>' },
    ], 'test');

    expect(findings.some((finding) => finding.sourceRule === 'CCPA-DNS-002')).toBe(true);
  });

  it('detects privacy policies missing CCPA category disclosures', () => {
    const findings = scanCcpaChecks([
      { relativePath: 'privacy.html', content: '<h1>Privacy Policy</h1><p>We collect personal information.</p>' },
    ], 'test');

    expect(findings.some((finding) => finding.sourceRule === 'CCPA-PP-001')).toBe(true);
  });

  it('detects privacy policies missing sale/disclosure info', () => {
    const findings = scanCcpaChecks([
      { relativePath: 'privacy.html', content: '<h1>Privacy Policy</h1><p>Categories of personal information are disclosed here.</p>' },
    ], 'test');

    expect(findings.some((finding) => finding.sourceRule === 'CCPA-PP-002')).toBe(true);
  });

  it('detects missing GPC handling and passes when GPC is handled', () => {
    const missing = scanCcpaChecks([
      { relativePath: 'src/privacy.ts', content: 'export const privacy = true;' },
    ], 'test');
    const handled = scanCcpaChecks([
      { relativePath: 'src/privacy.ts', content: 'if (navigator.globalPrivacyControl) optOut();' },
    ], 'test');

    expect(missing.some((finding) => finding.sourceRule === 'CCPA-GPC-001')).toBe(true);
    expect(handled.some((finding) => finding.sourceRule === 'CCPA-GPC-001')).toBe(false);
  });

  it('detects unencrypted sensitive PI in storage', () => {
    const findings = scanCcpaChecks([
      { relativePath: 'data/customers.json', content: '{"name":"Ada","ssn":"123-45-6789"}' },
    ], 'test');

    expect(findings).toContainEqual(expect.objectContaining({
      sourceRule: 'CCPA-SEC-001',
      category: 'ccpa-security',
      severity: 'critical',
      regulationMappings: [expect.objectContaining({
        jurisdiction: 'us-ccpa',
        principle: 'CCPA_150',
      })],
    }));
  });
});
