import { describe, expect, it } from 'vitest';

import { GDPR_CHECKS, scanGdprChecks } from './gdpr-checks.js';

describe('GDPR_CHECKS', () => {
  it('defines the requested GDPR scanner rules', () => {
    expect(GDPR_CHECKS.map((rule) => rule.id)).toEqual([
      'GDPR-CONSENT-001',
      'GDPR-PRIVACY-001',
      'GDPR-TRANSFER-001',
      'GDPR-DPIA-001',
      'GDPR-ART22-001',
      'GDPR-SEC-001',
    ]);
  });

  it('detects missing consent mechanism with negative detection', () => {
    const findings = scanGdprChecks([
      { relativePath: 'src/App.tsx', content: '<a href="/privacy">Privacy Policy</a>' },
    ], 'test');

    expect(findings.some((finding) => finding.sourceRule === 'GDPR-CONSENT-001')).toBe(true);
  });

  it('does not flag consent when a consent mechanism exists', () => {
    const findings = scanGdprChecks([
      { relativePath: 'src/App.tsx', content: '<button>Cookie consent preferences</button>' },
    ], 'test');

    expect(findings.some((finding) => finding.sourceRule === 'GDPR-CONSENT-001')).toBe(false);
  });

  it('detects privacy policies missing GDPR Art 13 disclosures', () => {
    const findings = scanGdprChecks([
      { relativePath: 'privacy.html', content: '<h1>Privacy Policy</h1><p>We collect personal data.</p>' },
    ], 'test');

    expect(findings.some((finding) => finding.sourceRule === 'GDPR-PRIVACY-001')).toBe(true);
  });

  it('does not flag complete GDPR privacy notice signals', () => {
    const findings = scanGdprChecks([
      {
        relativePath: 'privacy.html',
        content: [
          'Privacy Policy',
          'Contact our data protection officer.',
          'You may complain to a supervisory authority.',
          'You have the right to object.',
          'We disclose automated decision-making logic where used.',
        ].join('\n'),
      },
    ], 'test');

    expect(findings.some((finding) => finding.sourceRule === 'GDPR-PRIVACY-001')).toBe(false);
  });

  it('detects international transfers without safeguards', () => {
    const findings = scanGdprChecks([
      { relativePath: 'docs/privacy.md', content: 'We transfer personal data outside the EEA to third-country processors.' },
    ], 'test');

    expect(findings.some((finding) => finding.sourceRule === 'GDPR-TRANSFER-001')).toBe(true);
  });

  it('detects high-risk processing without DPIA documentation', () => {
    const findings = scanGdprChecks([
      { relativePath: 'src/profile.ts', content: 'export const profiling = computeRiskScore(user);' },
    ], 'test');

    expect(findings.some((finding) => finding.sourceRule === 'GDPR-DPIA-001')).toBe(true);
  });

  it('detects automated decisions without safeguards', () => {
    const findings = scanGdprChecks([
      { relativePath: 'src/eligibility.ts', content: 'const eligibilityScore = automatedDecision(applicant);' },
    ], 'test');

    expect(findings.some((finding) => finding.sourceRule === 'GDPR-ART22-001')).toBe(true);
  });

  it('marks negative-detection rules as advisory unknown findings', () => {
    const findings = scanGdprChecks([
      { relativePath: 'src/App.tsx', content: '<a href="/privacy">Privacy Policy</a>' },
      { relativePath: 'privacy.html', content: '<h1>Privacy Policy</h1><p>We collect personal data.</p>' },
      { relativePath: 'docs/privacy.md', content: 'We transfer personal data outside the EEA.' },
      { relativePath: 'src/profile.ts', content: 'export const profiling = automatedDecision(user);' },
    ], 'test');

    for (const ruleId of [
      'GDPR-CONSENT-001',
      'GDPR-PRIVACY-001',
      'GDPR-TRANSFER-001',
      'GDPR-DPIA-001',
      'GDPR-ART22-001',
    ]) {
      const finding = findings.find((candidate) => candidate.sourceRule === ruleId);
      expect(finding?.regulationMappings).toEqual([
        expect.objectContaining({
          jurisdiction: 'eu-gdpr',
          status: 'unknown',
          confidence: 0.5,
        }),
      ]);
      expect(finding?.description).toContain('Advisory only');
    }
  });

  it('detects plaintext special category data as a failing finding', () => {
    const findings = scanGdprChecks([
      { relativePath: 'data/patient.json', content: '{"name":"Ada","health_condition":"asthma"}' },
    ], 'test');

    expect(findings).toContainEqual(expect.objectContaining({
      sourceRule: 'GDPR-SEC-001',
      category: 'gdpr-security',
      severity: 'critical',
      regulationMappings: [expect.objectContaining({
        jurisdiction: 'eu-gdpr',
        principle: 'GDPR_Art9',
        status: 'fail',
        confidence: 0.85,
      })],
    }));
  });
});
