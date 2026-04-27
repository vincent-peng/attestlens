import { describe, it, expect } from 'vitest';
import { mapAllFindings, mapFindingToAPP, ALL_MAPPING_RULES } from './engine.js';
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
    const app11Rules = ALL_MAPPING_RULES.filter(r => r.appPrinciple === 'APP_11');
    expect(app11Rules.length).toBeGreaterThan(0);
  });

  it('should cover APP_6 (Use & Disclosure)', () => {
    const app6Rules = ALL_MAPPING_RULES.filter(r => r.appPrinciple === 'APP_6');
    expect(app6Rules.length).toBeGreaterThan(0);
  });

  it('should cover NDB (Data Breach Notification)', () => {
    const ndbRules = ALL_MAPPING_RULES.filter(r => r.appPrinciple === 'NDB');
    expect(ndbRules.length).toBeGreaterThan(0);
  });

  it('should only use valid APP principles', () => {
    const validPrinciples = [
      'APP_1', 'APP_2', 'APP_3', 'APP_4', 'APP_5', 'APP_6', 'APP_7',
      'APP_8', 'APP_9', 'APP_10', 'APP_11', 'APP_12', 'APP_13', 'NDB',
    ];
    for (const rule of ALL_MAPPING_RULES) {
      expect(validPrinciples).toContain(rule.appPrinciple);
    }
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
});
