import { describe, it, expect } from 'vitest';
import { buildComplianceReport, generateJSONReport, generateMarkdownReport } from './generator.js';
import type { AttestLensFinding } from '../schema/index.js';
import type { ReportOptions } from './generator.js';

function makeFinding(overrides: Partial<AttestLensFinding> = {}): AttestLensFinding {
  return {
    id: overrides.id || 'FIND-001',
    source: overrides.source || 'guardvibe',
    sourceRule: overrides.sourceRule || 'VS-HARDKEY',
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
  };
}

const defaultOptions: ReportOptions = {
  targetName: 'TestApp',
  targetPath: '/tmp/test',
  formats: ['json'],
  outputDir: '/tmp/attestlens-test',
  strictMode: false,
};

describe('buildComplianceReport', () => {
  it('should generate a report with all 14 APP controls', () => {
    const report = buildComplianceReport([], defaultOptions, 1000);
    expect(report.appControls.length).toBe(14);
  });

  it('should score 100 with no findings', () => {
    const report = buildComplianceReport([], defaultOptions, 1000);
    expect(report.overallScore).toBe(100);
    expect(report.overallGrade).toBe('A');
    expect(report.riskLevel).toBe('low');
  });

  it('should reduce score with critical findings', () => {
    const findings = [
      makeFinding({ id: 'F-1', severity: 'critical', sourceRule: 'VS-HARDKEY' }),
      makeFinding({ id: 'F-2', severity: 'critical', sourceRule: 'VS-ENV' }),
    ];
    const report = buildComplianceReport(findings, defaultOptions, 1000);
    expect(report.overallScore).toBeLessThan(100);
    expect(report.riskLevel).toBe('critical');
  });

  it('should mark APP_11 as fail for security findings', () => {
    const findings = [
      makeFinding({ id: 'F-1', severity: 'critical', sourceRule: 'VS-HARDKEY', title: 'Hardcoded key' }),
    ];
    const report = buildComplianceReport(findings, defaultOptions, 1000);
    const app11 = report.appControls.find(c => c.principle === 'APP_11');
    expect(app11!.status).toBe('fail');
  });

  it('should include remediation items', () => {
    const findings = [
      makeFinding({ id: 'F-1', severity: 'critical', sourceRule: 'VS-HARDKEY', title: 'Hardcoded key' }),
    ];
    const report = buildComplianceReport(findings, defaultOptions, 1000);
    expect(report.remediation.length).toBeGreaterThan(0);
  });

  it('should include scanner metadata', () => {
    const report = buildComplianceReport([], defaultOptions, 1000);
    expect(report.metadata.scanDurationMs).toBe(1000);
    expect(report.metadata.deterministicHash).toBeTruthy();
  });

  it('should include disclaimer', () => {
    const report = buildComplianceReport([], defaultOptions, 1000);
    expect(report.disclaimer).toContain('does not constitute legal advice');
  });
});

describe('generateJSONReport', () => {
  it('should produce valid JSON', () => {
    const report = buildComplianceReport([], defaultOptions, 1000);
    const json = generateJSONReport(report);
    const parsed = JSON.parse(json);
    expect(parsed.id).toBeTruthy();
    expect(parsed.appControls.length).toBe(14);
  });
});

describe('generateMarkdownReport', () => {
  it('should produce markdown with key sections', () => {
    const findings = [
      makeFinding({ id: 'F-1', severity: 'critical', sourceRule: 'VS-HARDKEY', title: 'Hardcoded key' }),
    ];
    const report = buildComplianceReport(findings, defaultOptions, 1000);
    const md = generateMarkdownReport(report);
    expect(md).toContain('# Privacy Act Compliance Report');
    expect(md).toContain('APP_11');
    expect(md).toContain('Hardcoded key');
  });
});