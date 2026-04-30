import { describe, it, expect, vi } from 'vitest';
import {
  ALL_MAPPING_RULES,
  CCPA_MAPPING_RULES,
  GDPR_MAPPING_RULES,
  mapAllFindings,
  mapAllFindingsAU,
  mapFindingToAPP,
  mapFindingToRegulation,
} from './engine.js';
import type { AttestLensFinding } from '../schema/index.js';

// ─── Test Fixtures ────────────────────────────────────────────────────────────

function makeFinding(overrides: Partial<AttestLensFinding> = {}): AttestLensFinding {
  return {
    id: overrides.id || 'FIND-001',
    source: overrides.source || 'guardvibe',
    sourceRule: overrides.sourceRule || 'VG-SEC-001',
    severity: overrides.severity || 'critical',
    category: overrides.category || 'Security',
    title: overrides.title || 'Test finding',
    description: overrides.description || 'A test finding',
    file: overrides.file || 'app.ts',
    line: overrides.line || 1,
    appMappings: [],
    evidence: {
      timestamp: new Date().toISOString(),
      scannerVersion: '0.1.0',
      rawOutput: {},
    },
    ...overrides,
  };
}

// ─── Mapping Rule Tests ──────────────────────────────────────────────────────

describe('ALL_MAPPING_RULES', () => {
  it('should have mapping rules defined', () => {
    expect(ALL_MAPPING_RULES.length).toBeGreaterThan(0);
  });

  it('should cover APP_11 (Security)', () => {
    const app11Rules = ALL_MAPPING_RULES.filter(r => r.regulationPrinciple === 'APP_11');
    expect(app11Rules.length).toBeGreaterThan(0);
  });

  it('should cover APP_6 (Use & Disclosure)', () => {
    const app6Rules = ALL_MAPPING_RULES.filter(r => r.regulationPrinciple === 'APP_6');
    expect(app6Rules.length).toBeGreaterThan(0);
  });

  it('should cover NDB (Data Breach Notification)', () => {
    const ndbRules = ALL_MAPPING_RULES.filter(r => r.regulationPrinciple === 'NDB');
    expect(ndbRules.length).toBeGreaterThan(0);
  });

  it('should only use valid principles for each jurisdiction', () => {
    const validPrinciples = [
      'APP_1', 'APP_2', 'APP_3', 'APP_4', 'APP_5', 'APP_6', 'APP_7',
      'APP_8', 'APP_9', 'APP_10', 'APP_11', 'APP_12', 'APP_13', 'NDB',
    ];
    const validCcpaPrinciples = [
      'CCPA_100', 'CCPA_105', 'CCPA_106', 'CCPA_110', 'CCPA_115', 'CCPA_120',
      'CCPA_121', 'CCPA_125', 'CCPA_130', 'CCPA_135', 'CCPA_145', 'CCPA_150',
    ];
    const validGdprPrinciples = [
      'GDPR_Art3', 'GDPR_Art5', 'GDPR_Art6', 'GDPR_Art9', 'GDPR_Art13',
      'GDPR_Art15', 'GDPR_Art17', 'GDPR_Art22', 'GDPR_Art25', 'GDPR_Art32',
      'GDPR_Art33', 'GDPR_Art34', 'GDPR_Art35', 'GDPR_Art44',
    ];
    for (const rule of ALL_MAPPING_RULES) {
      if (rule.jurisdiction === 'au-privacy-act') {
        expect(validPrinciples).toContain(rule.regulationPrinciple);
      } else if (rule.jurisdiction === 'us-ccpa') {
        expect(validCcpaPrinciples).toContain(rule.regulationPrinciple);
      } else if (rule.jurisdiction === 'eu-gdpr') {
        expect(validGdprPrinciples).toContain(rule.regulationPrinciple);
      } else {
        throw new Error(`Unexpected jurisdiction in mapping rule: ${rule.jurisdiction}`);
      }
    }
  });
});

describe('mapFindingToRegulation', () => {
  it('returns jurisdiction-aware regulation mappings', () => {
    const finding = makeFinding({
      sourceRule: 'VS-HARDKEY',
      severity: 'critical',
      title: 'Hardcoded secret key',
    });

    const mappings = mapFindingToRegulation(finding, ['au-privacy-act']);

    expect(mappings.length).toBeGreaterThan(0);
    expect(mappings.every(mapping => mapping.jurisdiction === 'au-privacy-act')).toBe(true);
    expect(mappings.some(mapping => mapping.principle === 'APP_11')).toBe(true);
  });

  it('includes citation metadata when the mapping rule has a citation', () => {
    const finding = makeFinding({
      sourceRule: 'VS-HARDKEY',
      severity: 'critical',
      title: 'Hardcoded secret key',
    });

    expect(mapFindingToRegulation(finding, ['au-privacy-act'])).toContainEqual(expect.objectContaining({
      principle: 'APP_11',
      citation: 'APP Guidelines Chapter 11.6',
    }));
  });

  it('maps security findings for CCPA', () => {
    const finding = makeFinding({
      sourceRule: 'VS-HARDKEY',
      severity: 'critical',
      title: 'Hardcoded secret key',
    });

    expect(mapFindingToRegulation(finding, ['us-ccpa'])).toEqual(expect.arrayContaining([
      expect.objectContaining({
        jurisdiction: 'us-ccpa',
        principle: 'CCPA_100',
        status: 'fail',
        confidence: 0.9,
        citation: 'Cal. Civ. Code §1798.100(e)',
      }),
      expect.objectContaining({
        jurisdiction: 'us-ccpa',
        principle: 'CCPA_150',
        status: 'fail',
        confidence: 0.85,
        citation: 'Cal. Civ. Code §1798.150(a)',
      }),
    ]));
  });

  it('maps security findings for GDPR', () => {
    const finding = makeFinding({
      sourceRule: 'VS-HARDKEY',
      severity: 'critical',
      title: 'Hardcoded secret key',
    });

    expect(mapFindingToRegulation(finding, ['eu-gdpr'])).toEqual(expect.arrayContaining([
      expect.objectContaining({
        jurisdiction: 'eu-gdpr',
        principle: 'GDPR_Art32',
        status: 'fail',
        confidence: 0.9,
        citation: 'GDPR Art. 32(1)',
      }),
    ]));
  });
});

// ─── mapFindingToAPP Tests ────────────────────────────────────────────────────

describe('mapFindingToAPP', () => {
  it('should map hardcoded secrets to APP_11 as fail', () => {
    const finding = makeFinding({
      sourceRule: 'VS-HARDKEY',
      severity: 'critical',
      title: 'Hardcoded secret key',
    });
    const mappings = mapFindingToAPP(finding);
    expect(mappings.length).toBeGreaterThan(0);
    const app11Mapping = mappings.find(m => m.principle === 'APP_11');
    expect(app11Mapping).toBeDefined();
    expect(app11Mapping!.status).toBe('fail');
  });

  it('should map XSS findings to APP_11 and APP_6', () => {
    const finding = makeFinding({
      sourceRule: 'VS-XSS',
      severity: 'medium',
      category: 'Security',
      title: 'Potential XSS vector',
    });
    const mappings = mapFindingToAPP(finding);
    expect(mappings.some(m => m.principle === 'APP_11')).toBe(true);
    expect(mappings.some(m => m.principle === 'APP_6')).toBe(true);
  });

  it('should map env exposure to APP_11 as fail', () => {
    const finding = makeFinding({
      sourceRule: 'VS-ENV',
      severity: 'critical',
      title: 'Sensitive env var exposed to client',
    });
    const mappings = mapFindingToAPP(finding);
    expect(mappings.some(m => m.principle === 'APP_11' && m.status === 'fail')).toBe(true);
  });

  it('should map SQL injection to APP_11 and APP_6', () => {
    const finding = makeFinding({
      sourceRule: 'VS-SQLI',
      severity: 'high',
      title: 'SQL injection vulnerability',
    });
    const mappings = mapFindingToAPP(finding);
    expect(mappings.some(m => m.principle === 'APP_11')).toBe(true);
    expect(mappings.some(m => m.principle === 'APP_6')).toBe(true);
  });

  it('should map debug logging to APP_6 and NDB', () => {
    const finding = makeFinding({
      sourceRule: 'VS-DEBUG',
      severity: 'medium',
      title: 'Debug logging of sensitive data',
    });
    const mappings = mapFindingToAPP(finding);
    expect(mappings.some(m => m.principle === 'APP_6')).toBe(true);
    expect(mappings.some(m => m.principle === 'NDB')).toBe(true);
  });

  it('should not map missing Cache-Control to APP_12', () => {
    const finding = makeFinding({
      sourceRule: 'AL-URL-011',
      severity: 'medium',
      category: 'Security Headers',
      title: 'Missing or Weak Cache-Control Header',
      description: 'Without proper Cache-Control, sensitive pages may be cached by browsers or CDNs, potentially exposing personal information.',
    });
    const mappings = mapFindingToAPP(finding);
    expect(mappings.some(m => m.principle === 'APP_11' && m.status === 'fail')).toBe(true);
    expect(mappings.some(m => m.principle === 'APP_12')).toBe(false);
  });

  it('should keep APP_11 failures for other security header findings', () => {
    const finding = makeFinding({
      sourceRule: 'AL-URL-001',
      severity: 'high',
      category: 'Security Headers',
      title: 'Missing Content-Security-Policy Header',
      description: 'Content-Security-Policy prevents XSS, clickjacking, and other code injection attacks.',
    });
    const mappings = mapFindingToAPP(finding);
    expect(mappings.some(m => m.principle === 'APP_11' && m.status === 'fail')).toBe(true);
  });

  it('should boost missing security header confidence on auth-sensitive URLs', () => {
    const neutral = makeFinding({
      source: 'url-scan',
      sourceRule: 'AL-URL-001',
      severity: 'high',
      category: 'Security Headers',
      title: 'Missing Content-Security-Policy Header',
      url: 'https://example.com/about',
    });
    const auth = makeFinding({
      ...neutral,
      id: 'FIND-AUTH',
      url: 'https://example.com/login',
      evidence: {
        timestamp: new Date().toISOString(),
        scannerVersion: '0.2.0',
        rawOutput: { url: 'https://example.com/login' },
      },
    });

    const neutralConfidence = mapFindingToAPP(neutral).find(m => m.principle === 'APP_11')!.confidence;
    const authConfidence = mapFindingToAPP(auth).find(m => m.principle === 'APP_11')!.confidence;
    expect(authConfidence).toBeGreaterThan(neutralConfidence);
  });

  it('should reduce confidence for secrets in template env files', () => {
    const realEnv = makeFinding({
      sourceRule: 'VS-ENV',
      severity: 'critical',
      title: '.env exposed',
      file: '.env',
    });
    const templateEnv = makeFinding({
      ...realEnv,
      id: 'FIND-TEMPLATE',
      file: '.env.example',
    });

    const realConfidence = mapFindingToAPP(realEnv).find(m => m.principle === 'APP_11')!.confidence;
    const templateConfidence = mapFindingToAPP(templateEnv).find(m => m.principle === 'APP_11')!.confidence;
    expect(templateConfidence).toBeLessThan(realConfidence);
  });

  it('should map unmapped high-severity Security findings to APP_11 as unknown', () => {
    const finding = makeFinding({
      sourceRule: 'CUSTOM-RULE-999',
      severity: 'high',
      title: 'Custom security issue',
    });
    const mappings = mapFindingToAPP(finding);
    // High-severity Security findings without explicit rules default to APP_11
    expect(mappings.some(m => m.principle === 'APP_11')).toBe(true);
  });

  it('should still map low severity Security category findings to APP_11', () => {
    const finding = makeFinding({
      sourceRule: 'CUSTOM-RULE-999',
      severity: 'low',
      category: 'Security',
      title: 'Minor issue',
    });
    const mappings = mapFindingToAPP(finding);
    // Security category matches APP_11 regardless of severity
    expect(mappings.some(m => m.principle === 'APP_11')).toBe(true);
  });

  it('should map OSV dependency vulnerabilities to APP_11', () => {
    const finding = makeFinding({
      source: 'supply-chain',
      sourceRule: 'VS-OSV-GHSA-test-1234',
      severity: 'high',
      category: 'Security',
      title: 'OSV vulnerability in "pkg": Authentication bypass',
    });
    const mappings = mapFindingToAPP(finding);
    const app11Mapping = mappings.find(m => m.principle === 'APP_11' && m.status === 'fail');
    expect(app11Mapping).toBeDefined();
    expect(app11Mapping!.confidence).toBeGreaterThanOrEqual(0.9);
  });

  it('should preserve OSV-derived mappings after npm audit dedup merge', () => {
    const finding = makeFinding({
      source: 'supply-chain',
      sourceRule: 'VS-SC-006',
      severity: 'critical',
      category: 'Security',
      title: 'Known vulnerability in "pkg": npm advisory',
      description: 'npm audit found a critical vulnerability in "pkg".',
      evidence: {
        timestamp: new Date().toISOString(),
        scannerVersion: '0.2.0',
        rawOutput: {
          packageName: 'pkg',
          osvSourceRule: 'VS-OSV-GHSA-abcd-1234-wxyz',
          osvFindingTitle: 'OSV vulnerability in "pkg": Authentication bypass SSRF exfiltration',
          osvFindingDescription: 'OSV reports GHSA-abcd-1234-wxyz for "pkg" at version 1.0.0.',
        },
      },
    });

    const mappings = mapFindingToAPP(finding);
    expect(mappings.some(m => m.principle === 'APP_11' && m.status === 'fail')).toBe(true);
    expect(mappings.some(m => m.principle === 'APP_8' && m.status === 'unknown')).toBe(true);
    expect(mappings.some(m => m.principle === 'NDB' && m.status === 'unknown')).toBe(true);
    expect(Math.max(...mappings.map(m => m.confidence))).toBeGreaterThan(0.9);
  });

  it('should lower typosquat confidence as edit distance increases', () => {
    const distanceOne = makeFinding({
      source: 'supply-chain',
      sourceRule: 'VS-SC-004',
      severity: 'critical',
      category: 'Security',
      title: 'Potential typosquat: "lodas" resembles "lodash"',
      evidence: {
        timestamp: new Date().toISOString(),
        scannerVersion: '0.2.0',
        rawOutput: { packageName: 'lodas', typosquatTarget: 'lodash', typosquatDistance: 1 },
      },
    });
    const distanceTwo = makeFinding({
      ...distanceOne,
      id: 'FIND-DIST-2',
      evidence: {
        timestamp: new Date().toISOString(),
        scannerVersion: '0.2.0',
        rawOutput: { packageName: 'loash', typosquatTarget: 'lodash', typosquatDistance: 2 },
      },
    });

    const confidenceOne = mapFindingToAPP(distanceOne).find(m => m.principle === 'APP_11')!.confidence;
    const confidenceTwo = mapFindingToAPP(distanceTwo).find(m => m.principle === 'APP_11')!.confidence;
    expect(confidenceOne).toBeGreaterThan(confidenceTwo);
  });

  it('should map missing dependency provenance to APP_11 and APP_6', () => {
    const finding = makeFinding({
      source: 'supply-chain',
      sourceRule: 'VS-SC-009',
      severity: 'medium',
      category: 'Security',
      title: 'Dependency "pkg" has no source repository or homepage',
    });
    const mappings = mapFindingToAPP(finding);
    expect(mappings.some(m => m.principle === 'APP_11' && m.status === 'fail')).toBe(true);
    expect(mappings.some(m => m.principle === 'APP_6' && m.status === 'unknown')).toBe(true);
  });

  it('should map low-maturity dependency findings to APP_11 and boost high-risk maturity confidence', () => {
    const lowRisk = makeFinding({
      source: 'supply-chain',
      sourceRule: 'VS-SC-010',
      severity: 'medium',
      category: 'Supply Chain Maturity',
      title: 'Dependency has weak package maturity signals',
      evidence: {
        timestamp: new Date().toISOString(),
        scannerVersion: '0.2.0',
        rawOutput: { packageName: 'pkg', maturityRisk: 0.55 },
      },
    });
    const highRisk = makeFinding({
      ...lowRisk,
      id: 'FIND-MATURITY-HIGH',
      evidence: {
        timestamp: new Date().toISOString(),
        scannerVersion: '0.2.0',
        rawOutput: { packageName: 'pkg', maturityRisk: 0.9 },
      },
    });

    const lowRiskMapping = mapFindingToAPP(lowRisk).find(m => m.principle === 'APP_11');
    const highRiskMapping = mapFindingToAPP(highRisk).find(m => m.principle === 'APP_11');
    expect(lowRiskMapping?.status).toBe('unknown');
    expect(highRiskMapping!.confidence).toBeGreaterThan(lowRiskMapping!.confidence);
  });

  it('should map behavioral dependency findings to APP_11 with conditional secondary obligations', () => {
    const networkFinding = makeFinding({
      source: 'behavioral',
      sourceRule: 'VS-BH-002',
      severity: 'medium',
      category: 'Behavioral Supply Chain',
      title: 'Dependency can make network requests',
      description: 'Network-capable dependency',
    });
    const envFinding = makeFinding({
      source: 'behavioral',
      sourceRule: 'VS-BH-004',
      severity: 'medium',
      category: 'Behavioral Supply Chain',
      title: 'Dependency reads environment variables',
      description: 'Secret-adjacent dependency behavior',
    });

    expect(mapFindingToAPP(networkFinding).map(mapping => mapping.principle)).toEqual(['APP_11', 'APP_8']);
    expect(mapFindingToAPP(envFinding).map(mapping => mapping.principle)).toEqual(['APP_11', 'NDB']);
  });

  it('should map gitleaks findings to APP_11 and NDB', () => {
    const finding = makeFinding({
      source: 'gitleaks',
      sourceRule: 'VS-GL-GITHUB-PAT',
      severity: 'high',
      category: 'Developer Credentials',
      title: 'Secret detected in git history',
      description: 'gitleaks detected a GitHub PAT',
    });

    expect(mapFindingToAPP(finding).map(mapping => mapping.principle)).toEqual(['APP_11', 'NDB']);
  });

  it('should map SAST-lite findings to APP/NDB obligations', () => {
    const ssrf = makeFinding({
      source: 'guardvibe',
      sourceRule: 'VS-SAST-006',
      severity: 'high',
      category: 'SAST Lite',
      title: 'Outbound request uses untrusted URL input',
    });
    const collection = makeFinding({
      source: 'guardvibe',
      sourceRule: 'VS-SAST-019',
      severity: 'medium',
      category: 'SAST Lite',
      title: 'Personal data collected without visible consent check',
    });

    expect(mapFindingToAPP(ssrf).map(mapping => mapping.principle)).toEqual(['APP_11', 'APP_8']);
    expect(mapFindingToAPP(collection).map(mapping => mapping.principle)).toEqual(['APP_11', 'APP_3']);
  });

  it('should increase mapping confidence for corroborated cross-scanner findings', () => {
    const singleSource = makeFinding({
      sourceRule: 'VS-XSS',
      severity: 'medium',
      category: 'Security',
      title: 'Potential XSS vector',
    });
    const corroborated = makeFinding({
      ...singleSource,
      id: 'FIND-CORROBORATED',
      corroboratedBy: ['url-scan'],
    });

    const singleConfidence = mapFindingToAPP(singleSource).find(m => m.principle === 'APP_11')!.confidence;
    const corroboratedConfidence = mapFindingToAPP(corroborated).find(m => m.principle === 'APP_11')!.confidence;
    expect(corroboratedConfidence).toBeGreaterThan(singleConfidence);
  });
});

describe('CCPA_MAPPING_RULES', () => {
  const cases = [
    {
      ruleId: 'MAP-CCPA-001',
      finding: makeFinding({ sourceRule: 'VS-HARDKEY', severity: 'high', title: 'Hardcoded secret key' }),
      principle: 'CCPA_100',
      confidence: 0.90,
      citation: 'Cal. Civ. Code §1798.100(e)',
    },
    {
      ruleId: 'MAP-CCPA-002',
      finding: makeFinding({ sourceRule: 'VS-SQLI', severity: 'high', title: 'SQL injection vulnerability' }),
      principle: 'CCPA_100',
      confidence: 0.90,
      citation: 'Cal. Civ. Code §1798.100(e)',
    },
    {
      ruleId: 'MAP-CCPA-003',
      finding: makeFinding({ sourceRule: 'VS-XSS', severity: 'medium', title: 'Potential XSS vector' }),
      principle: 'CCPA_100',
      confidence: 0.85,
      citation: 'Cal. Civ. Code §1798.100(e)',
    },
    {
      ruleId: 'MAP-CCPA-004',
      finding: makeFinding({ source: 'url-scan', sourceRule: 'AL-URL-002', severity: 'high', category: 'Security Headers', title: 'Missing Strict-Transport-Security Header' }),
      principle: 'CCPA_100',
      confidence: 0.90,
      citation: 'Cal. Civ. Code §1798.100(e)',
    },
    {
      ruleId: 'MAP-CCPA-005',
      finding: makeFinding({ sourceRule: 'VS-HARDKEY', severity: 'critical', title: 'Hardcoded secret key' }),
      principle: 'CCPA_150',
      confidence: 0.85,
      citation: 'Cal. Civ. Code §1798.150(a)',
    },
    {
      ruleId: 'MAP-CCPA-006',
      finding: makeFinding({ category: 'Data Leak', title: 'Data leak exposure', severity: 'high' }),
      principle: 'CCPA_150',
      confidence: 0.80,
      citation: 'Cal. Civ. Code §1798.150(a)',
    },
    {
      ruleId: 'MAP-CCPA-007',
      finding: makeFinding({ title: 'Plaintext SSN stored in data store', severity: 'critical' }),
      principle: 'CCPA_150',
      confidence: 0.85,
      citation: 'Cal. Civ. Code §1798.150(a)',
    },
    {
      ruleId: 'MAP-CCPA-008',
      finding: makeFinding({ category: 'third-party sharing', title: 'Third-party transfer', severity: 'medium' }),
      principle: 'CCPA_100',
      confidence: 0.70,
      citation: 'Cal. Civ. Code §1798.100(d)',
    },
    {
      ruleId: 'MAP-CCPA-009',
      finding: makeFinding({ title: 'Excessive data collection', severity: 'medium' }),
      principle: 'CCPA_100',
      confidence: 0.65,
      citation: 'Cal. Civ. Code §1798.100(c)',
    },
  ];

  it('defines all requested CCPA mapping rules', () => {
    expect(CCPA_MAPPING_RULES.map((rule) => rule.id)).toEqual([
      'MAP-CCPA-001',
      'MAP-CCPA-002',
      'MAP-CCPA-003',
      'MAP-CCPA-004',
      'MAP-CCPA-005',
      'MAP-CCPA-006',
      'MAP-CCPA-007',
      'MAP-CCPA-008',
      'MAP-CCPA-009',
    ]);
  });

  for (const testCase of cases) {
    it(`${testCase.ruleId} maps to ${testCase.principle}`, () => {
      const rule = CCPA_MAPPING_RULES.find((candidate) => candidate.id === testCase.ruleId)!;
      const mappings = mapFindingToRegulation(testCase.finding, ['us-ccpa']);
      expect(mappings).toContainEqual(expect.objectContaining({
        jurisdiction: 'us-ccpa',
        principle: testCase.principle,
        status: rule.status,
        confidence: testCase.confidence,
        citation: testCase.citation,
      }));
    });
  }
});

describe('GDPR_MAPPING_RULES', () => {
  const cases = [
    {
      ruleId: 'MAP-GDPR-001',
      finding: makeFinding({ sourceRule: 'VS-HARDKEY', severity: 'high', title: 'Hardcoded secret key' }),
      principle: 'GDPR_Art32',
      status: 'fail',
      confidence: 0.90,
      citation: 'GDPR Art. 32(1)',
    },
    {
      ruleId: 'MAP-GDPR-002',
      finding: makeFinding({ sourceRule: 'VS-SQLI', severity: 'high', title: 'SQL injection vulnerability' }),
      principle: 'GDPR_Art32',
      status: 'fail',
      confidence: 0.90,
      citation: 'GDPR Art. 32(1)',
    },
    {
      ruleId: 'MAP-GDPR-003',
      finding: makeFinding({ sourceRule: 'VS-XSS', severity: 'medium', title: 'Potential XSS vector' }),
      principle: 'GDPR_Art32',
      status: 'fail',
      confidence: 0.85,
      citation: 'GDPR Art. 32(1)',
    },
    {
      ruleId: 'MAP-GDPR-004',
      finding: makeFinding({ source: 'url-scan', sourceRule: 'AL-URL-002', severity: 'high', category: 'Security Headers', title: 'Missing Strict-Transport-Security Header' }),
      principle: 'GDPR_Art32',
      status: 'fail',
      confidence: 0.90,
      citation: 'GDPR Art. 32(1)',
    },
    {
      ruleId: 'MAP-GDPR-005',
      finding: makeFinding({ title: 'Plaintext SSN stored in data store', severity: 'critical' }),
      principle: 'GDPR_Art32',
      status: 'fail',
      confidence: 0.85,
      citation: 'GDPR Art. 32(1)(a)',
    },
    {
      ruleId: 'MAP-GDPR-006',
      finding: makeFinding({ category: 'Data Leak', title: 'Data leak exposure', severity: 'high' }),
      principle: 'GDPR_Art33',
      status: 'fail',
      confidence: 0.80,
      citation: 'GDPR Art. 33(1)',
    },
    {
      ruleId: 'MAP-GDPR-007',
      finding: makeFinding({ category: 'third-party transfer', title: 'Third-party transfer', severity: 'medium' }),
      principle: 'GDPR_Art44',
      status: 'unknown',
      confidence: 0.60,
      citation: 'GDPR Art. 44',
    },
    {
      ruleId: 'MAP-GDPR-008',
      finding: makeFinding({ title: 'Excessive data collection', severity: 'medium' }),
      principle: 'GDPR_Art5',
      status: 'unknown',
      confidence: 0.55,
      citation: 'GDPR Art. 5(1)(c)',
    },
    {
      ruleId: 'MAP-GDPR-009',
      finding: makeFinding({ category: 'automated decision', title: 'Automated decision system', severity: 'medium' }),
      principle: 'GDPR_Art22',
      status: 'unknown',
      confidence: 0.50,
      citation: 'GDPR Art. 22(1)',
    },
  ];

  it('defines all requested GDPR mapping rules', () => {
    expect(GDPR_MAPPING_RULES.map((rule) => rule.id)).toEqual([
      'MAP-GDPR-001',
      'MAP-GDPR-002',
      'MAP-GDPR-003',
      'MAP-GDPR-004',
      'MAP-GDPR-005',
      'MAP-GDPR-006',
      'MAP-GDPR-007',
      'MAP-GDPR-008',
      'MAP-GDPR-009',
    ]);
  });

  for (const testCase of cases) {
    it(`${testCase.ruleId} maps to ${testCase.principle}`, () => {
      const mappings = mapFindingToRegulation(testCase.finding, ['eu-gdpr']);
      expect(mappings).toContainEqual(expect.objectContaining({
        jurisdiction: 'eu-gdpr',
        principle: testCase.principle,
        status: testCase.status,
        confidence: testCase.confidence,
        citation: testCase.citation,
      }));
    });
  }

  it('keeps advisory GDPR mappings as unknown', () => {
    const advisoryMappings = [
      mapFindingToRegulation(makeFinding({ category: 'third-party transfer', title: 'Third-party transfer' }), ['eu-gdpr']),
      mapFindingToRegulation(makeFinding({ title: 'Excessive data collection' }), ['eu-gdpr']),
      mapFindingToRegulation(makeFinding({ category: 'automated decision', title: 'Automated decision system' }), ['eu-gdpr']),
    ].flat();

    expect(advisoryMappings).toEqual(expect.arrayContaining([
      expect.objectContaining({ principle: 'GDPR_Art44', status: 'unknown' }),
      expect.objectContaining({ principle: 'GDPR_Art5', status: 'unknown' }),
      expect.objectContaining({ principle: 'GDPR_Art22', status: 'unknown' }),
    ]));
  });
});

// ─── mapAllFindings Tests ─────────────────────────────────────────────────────

describe('mapAllFindings', () => {
  it('should initialize all 14 APP principles as unknown', () => {
    const { controls } = mapAllFindings([]);
    expect(controls.length).toBe(14);
    for (const control of controls) {
      expect(control.status).toBe('unknown');
      expect(control.score).toBe(100);
    }
  });

  it('accepts the legacy boolean strict-mode argument', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-01-01T00:00:00.000Z'));

    try {
      const legacy = mapAllFindings([], true);
      const options = mapAllFindings([], { strictMode: true });

      expect(legacy).toEqual(options);
      expect(legacy.controls).toHaveLength(14);
      expect(legacy.controls.every(control => control.status === 'fail')).toBe(true);
      expect(legacy.controls.every(control => control.score === 0)).toBe(true);
      expect(legacy.controls.every(control => control.questionnaireRequired === false)).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it('should mark APP_11 as fail when critical security findings exist', () => {
    const findings: AttestLensFinding[] = [
      makeFinding({
        id: 'F-1',
        sourceRule: 'VS-HARDKEY',
        severity: 'critical',
        title: 'Hardcoded secret key',
      }),
    ];
    const { controls } = mapAllFindings(findings);
    const app11 = controls.find(c => c.principle === 'APP_11');
    expect(app11!.status).toBe('fail');
    expect(app11!.score).toBeLessThan(100);
    // A single critical finding can map to APP_11 multiple times (multiple rules match)
    expect(app11!.findingCount.critical).toBeGreaterThanOrEqual(1);
  });

  it('should use worst status per principle (fail overrides pass)', () => {
    const findings: AttestLensFinding[] = [
      makeFinding({
        id: 'F-1',
        sourceRule: 'VS-SEC-PASS',
        severity: 'info',
        title: 'CORS headers configured',
      }),
      makeFinding({
        id: 'F-2',
        sourceRule: 'VS-HARDKEY',
        severity: 'critical',
        title: 'Hardcoded secret key',
      }),
    ];
    const { controls } = mapAllFindings(findings);
    const app11 = controls.find(c => c.principle === 'APP_11');
    // Hardcoded key maps to APP_11 as fail — should override any pass
    expect(app11!.status).toBe('fail');
  });

  it('should deduct score based on finding severity', () => {
    const findings: AttestLensFinding[] = [
      makeFinding({
        id: 'F-1',
        sourceRule: 'VS-HARDKEY',
        severity: 'critical',
        title: 'Hardcoded secret key',
      }),
      makeFinding({
        id: 'F-2',
        sourceRule: 'VS-XSS',
        severity: 'medium',
        title: 'XSS vector',
      }),
    ];
    const { controls } = mapAllFindings(findings);
    const app11 = controls.find(c => c.principle === 'APP_11');
    // critical = -15, medium = -5 (multiple times due to overlapping rules)
    expect(app11!.score).toBeLessThan(100);
  });

  it('should track findings with no APP mappings as unmapped', () => {
    const findings: AttestLensFinding[] = [
      makeFinding({
        id: 'F-1',
        sourceRule: 'UNKNOWN-RULE',
        severity: 'low',
        category: 'Performance',  // Not 'Security' — won't match any rule
        title: 'Random low-sev issue',
      }),
    ];
    const { unmapped } = mapAllFindings(findings);
    expect(unmapped.length).toBe(1);
    expect(unmapped[0].id).toBe('F-1');
  });

  it('should set questionnaireRequired to false for principles with findings', () => {
    const findings: AttestLensFinding[] = [
      makeFinding({
        id: 'F-1',
        sourceRule: 'VS-HARDKEY',
        severity: 'critical',
        title: 'Hardcoded secret key',
      }),
    ];
    const { controls } = mapAllFindings(findings);
    const app11 = controls.find(c => c.principle === 'APP_11');
    expect(app11!.questionnaireRequired).toBe(false);
  });

  it('should set questionnaireRequired to true for principles without findings', () => {
    const { controls } = mapAllFindings([]);
    for (const control of controls) {
      expect(control.questionnaireRequired).toBe(true);
    }
  });

  it('should leave APP_12 unknown when only Cache-Control is missing', () => {
    const { controls } = mapAllFindings([
      makeFinding({
        id: 'F-1',
        sourceRule: 'AL-URL-011',
        severity: 'medium',
        category: 'Security Headers',
        title: 'Missing or Weak Cache-Control Header',
        description: 'Without proper Cache-Control, sensitive pages may be cached by browsers or CDNs, potentially exposing personal information.',
      }),
    ]);

    const app11 = controls.find(c => c.principle === 'APP_11');
    const app12 = controls.find(c => c.principle === 'APP_12');

    expect(app11!.status).toBe('fail');
    expect(app12!.status).toBe('unknown');
  });

  it('maps CCPA controls for US CCPA jurisdiction', () => {
    const { controls, unmapped } = mapAllFindings([
      makeFinding({
        id: 'F-1',
        sourceRule: 'VS-HARDKEY',
        severity: 'critical',
        title: 'Hardcoded secret key',
      }),
    ], { jurisdictions: ['us-ccpa'] });

    const ccpa100 = controls.find(c => c.jurisdiction === 'us-ccpa' && c.principle === 'CCPA_100');
    const ccpa150 = controls.find(c => c.jurisdiction === 'us-ccpa' && c.principle === 'CCPA_150');
    expect(controls).toHaveLength(12);
    expect(ccpa100?.status).toBe('fail');
    expect(ccpa150?.status).toBe('fail');
    expect(unmapped).toEqual([]);
  });

  it('maps GDPR security and breach findings for EU GDPR jurisdiction', () => {
    const { controls, unmapped } = mapAllFindings([
      makeFinding({
        id: 'F-1',
        sourceRule: 'VS-HARDKEY',
        severity: 'critical',
        title: 'Hardcoded secret key',
      }),
      makeFinding({
        id: 'F-2',
        sourceRule: 'GDPR-LEAK',
        category: 'Data Leak',
        severity: 'high',
        title: 'Data leak exposure',
      }),
    ], { jurisdictions: ['eu-gdpr'] });

    const art32 = controls.find(c => c.jurisdiction === 'eu-gdpr' && c.principle === 'GDPR_Art32');
    const art33 = controls.find(c => c.jurisdiction === 'eu-gdpr' && c.principle === 'GDPR_Art33');
    expect(controls).toHaveLength(14);
    expect(art32?.status).toBe('fail');
    expect(art33?.status).toBe('fail');
    expect(unmapped).toEqual([]);
  });

  it('merges selected jurisdictions while preserving AU controls', () => {
    const finding = makeFinding({
      id: 'F-1',
      sourceRule: 'VS-HARDKEY',
      severity: 'critical',
      title: 'Hardcoded secret key',
    });

    const { controls } = mapAllFindings([finding], {
      jurisdictions: ['au-privacy-act', 'us-ccpa'],
    });

    expect(controls.some(control => control.jurisdiction === 'au-privacy-act' && control.principle === 'APP_11')).toBe(true);
    expect(controls.some(control => control.jurisdiction === 'us-ccpa' && control.principle === 'CCPA_100')).toBe(true);
    expect(finding.regulationMappings?.some(mapping => mapping.jurisdiction === 'au-privacy-act')).toBe(true);
    expect(finding.regulationMappings?.some(mapping => mapping.jurisdiction === 'us-ccpa')).toBe(true);
  });

  it('maps selected findings across AU, CCPA, and GDPR jurisdictions', () => {
    const finding = makeFinding({
      id: 'F-1',
      sourceRule: 'VS-HARDKEY',
      severity: 'critical',
      title: 'Hardcoded secret key',
    });

    const { controls } = mapAllFindings([finding], {
      jurisdictions: ['au-privacy-act', 'us-ccpa', 'eu-gdpr'],
    });

    expect(controls.some(control => control.jurisdiction === 'au-privacy-act' && control.principle === 'APP_11')).toBe(true);
    expect(controls.some(control => control.jurisdiction === 'us-ccpa' && control.principle === 'CCPA_100')).toBe(true);
    expect(controls.some(control => control.jurisdiction === 'eu-gdpr' && control.principle === 'GDPR_Art32')).toBe(true);
    expect(finding.regulationMappings?.some(mapping => mapping.jurisdiction === 'au-privacy-act')).toBe(true);
    expect(finding.regulationMappings?.some(mapping => mapping.jurisdiction === 'us-ccpa')).toBe(true);
    expect(finding.regulationMappings?.some(mapping => mapping.jurisdiction === 'eu-gdpr')).toBe(true);
  });

  it('keeps the AU compatibility wrapper APP-shaped', () => {
    const { controls } = mapAllFindingsAU([
      makeFinding({
        sourceRule: 'VS-HARDKEY',
        severity: 'critical',
        title: 'Hardcoded secret key',
      }),
    ]);

    const app11 = controls.find(control => control.principle === 'APP_11');
    expect(app11).toBeDefined();
    expect('jurisdiction' in app11!).toBe(false);
  });
});
