import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import type { AttestLensFinding } from '../schema/index.js';
import {
  buildJurisdictionQualifiedRuleId,
  buildPrimaryLocationLineHash,
  formatSarif,
  inferSarifPrecision,
  mapDeployDecisionToSarifLevel,
  mapFindingSeverityToSarifLevel,
} from './sarif.js';

function makeFinding(overrides: Partial<AttestLensFinding> = {}): AttestLensFinding {
  return {
    id: 'finding-1',
    source: 'guardvibe',
    sourceRule: 'VS-HARDKEY',
    severity: 'high',
    category: 'Secrets',
    title: 'Privacy policy accessible',
    description: 'Privacy policy not found or not accessible from homepage',
    file: 'src/pages/index.tsx',
    line: 42,
    regulationMappings: [
      {
        jurisdiction: 'au-privacy-act',
        principle: 'APP_11',
        obligation: 'Take reasonable steps to protect personal information',
        status: 'fail',
        confidence: 0.9,
        citation: 'APP Guidelines Chapter 11.6',
      },
      {
        jurisdiction: 'eu-gdpr',
        principle: 'GDPR_Art13',
        obligation: 'Provide privacy notice information to data subjects',
        status: 'fail',
        confidence: 0.5,
        citation: 'GDPR Art. 13-14',
      },
    ],
    appMappings: [],
    evidence: {
      timestamp: new Date().toISOString(),
      scannerVersion: '0.4.0',
      rawOutput: {},
    },
    ...overrides,
  };
}

describe('SARIF formatter', () => {
  const cleanup: string[] = [];

  afterEach(async () => {
    await Promise.all(cleanup.splice(0).map((target) => fs.rm(target, { recursive: true, force: true })));
  });

  it('builds SARIF output with jurisdiction-qualified rule IDs and relative file paths', async () => {
    const projectDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-sarif-'));
    cleanup.push(projectDir);
    const filePath = path.join(projectDir, 'src', 'pages', 'index.tsx');
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    await fs.writeFile(filePath, 'export const page = true;\n', 'utf-8');

    const sarif = await formatSarif({
      findings: [makeFinding({ file: filePath })],
      jurisdiction: 'au-privacy-act',
      version: '0.4.0',
      basePath: projectDir,
    });

    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0]!.tool.driver.name).toBe('Clearway');
    expect(sarif.runs[0]!.tool.driver.rules[0]!.id).toBe('AU.APP.11.1.privacy-policy-accessible');
    expect(sarif.runs[0]!.results[0]!.locations[0]!.physicalLocation.artifactLocation.uri).toBe('src/pages/index.tsx');
    expect(sarif.runs[0]!.results[0]!.partialFingerprints.primaryLocationLineHash).toBe(
      buildPrimaryLocationLineHash('AU.APP.11.1.privacy-policy-accessible', 'src/pages/index.tsx', 42),
    );
    expect(sarif.runs[0]!.tool.driver.rules[0]!.properties).toEqual({
      tags: ['privacy', 'au-privacy-act', 'app-11'],
      precision: 'high',
      'problem.severity': 'error',
    });
  });

  it('supports zero findings', async () => {
    const sarif = await formatSarif({
      findings: [],
      jurisdiction: 'eu-gdpr',
      version: '0.4.0',
    });

    expect(sarif.runs[0]!.results).toEqual([]);
    expect(sarif.runs[0]!.tool.driver.rules).toEqual([]);
  });

  it('skips findings that do not have a mapping for the requested jurisdiction', async () => {
    const sarif = await formatSarif({
      findings: [
        makeFinding({
          regulationMappings: [
            {
              jurisdiction: 'au-privacy-act',
              principle: 'APP_11',
              obligation: 'Take reasonable steps to protect personal information',
              status: 'fail',
              confidence: 0.9,
              citation: 'APP Guidelines Chapter 11.6',
            },
          ],
        }),
      ],
      jurisdiction: 'eu-gdpr',
      version: '0.4.0',
    });

    expect(sarif.runs[0]!.results).toEqual([]);
    expect(sarif.runs[0]!.tool.driver.rules).toEqual([]);
  });

  it('uses a synthetic relative location when a finding has no file path', async () => {
    const sarif = await formatSarif({
      findings: [makeFinding({ file: undefined, line: undefined, severity: 'low' })],
      jurisdiction: 'eu-gdpr',
      version: '0.4.0',
    });

    const result = sarif.runs[0]!.results[0]!;
    expect(result.ruleId).toBe('EU.GDPR.ART.13.privacy-policy-accessible');
    expect(result.level).toBe('note');
    expect(result.locations[0]!.physicalLocation.artifactLocation.uri).toBe('__target__');
    expect(result.locations[0]!.physicalLocation.region.startLine).toBe(1);
  });

  it('maps severities and precision consistently', () => {
    expect(mapFindingSeverityToSarifLevel('critical')).toBe('error');
    expect(mapFindingSeverityToSarifLevel('medium')).toBe('warning');
    expect(mapFindingSeverityToSarifLevel('info')).toBe('note');
    expect(mapDeployDecisionToSarifLevel({
      verdict: 'BLOCK',
      blocking: true,
      confidence: 0.9,
      jurisdiction: 'au-privacy-act',
      packValidationStatus: 'external_reviewed',
      reasons: [],
      evidenceRefs: [],
      remediations: [],
    })).toBe('error');
    expect(inferSarifPrecision(makeFinding({ severity: 'medium' }))).toBe('medium');
    expect(inferSarifPrecision(makeFinding({ severity: 'high', corroboratedBy: ['gitleaks'] }))).toBe('very-high');
  });

  it('maps deploy decisions to SARIF levels', async () => {
    const warningSarif = await formatSarif({
      findings: [makeFinding({ severity: 'critical' })],
      jurisdiction: 'au-privacy-act',
      version: '0.4.0',
      deployDecision: {
        verdict: 'WARN',
        blocking: false,
        confidence: 0.8,
        jurisdiction: 'au-privacy-act',
        packValidationStatus: 'internal_validated',
        reasons: ['Weakly validated pack should warn instead of block.'],
        evidenceRefs: ['ev-chain:finding:finding-1'],
        remediations: [],
      },
    });

    expect(warningSarif.runs[0]!.results[0]!.level).toBe('warning');
    expect(warningSarif.runs[0]!.tool.driver.rules[0]!.properties['problem.severity']).toBe('warning');

    const reviewSarif = await formatSarif({
      findings: [makeFinding({ severity: 'low' })],
      jurisdiction: 'au-privacy-act',
      version: '0.4.0',
      deployDecision: {
        verdict: 'NEEDS_REVIEW',
        blocking: false,
        confidence: 0.5,
        jurisdiction: 'au-privacy-act',
        packValidationStatus: 'internal_validated',
        reasons: ['Contextual issue needs review.'],
        evidenceRefs: ['ev-chain:finding:finding-1'],
        remediations: [],
      },
    });

    expect(reviewSarif.runs[0]!.results[0]!.level).toBe('note');
    expect(reviewSarif.runs[0]!.tool.driver.rules[0]!.properties['problem.severity']).toBe('recommendation');
  });

  it('applies deploy decision levels only to referenced evidence findings', async () => {
    const sarif = await formatSarif({
      findings: [
        makeFinding({
          id: 'blocking-finding',
          title: 'Blocking privacy issue',
          severity: 'high',
        }),
        makeFinding({
          id: 'unrelated-finding',
          title: 'Unrelated informational issue',
          severity: 'info',
        }),
      ],
      jurisdiction: 'au-privacy-act',
      version: '0.4.0',
      deployDecision: {
        verdict: 'BLOCK',
        blocking: true,
        confidence: 0.95,
        jurisdiction: 'au-privacy-act',
        packValidationStatus: 'external_reviewed',
        reasons: ['Blocking issue prevents deploy.'],
        evidenceRefs: ['ev-chain:finding:blocking-finding'],
        remediations: [],
      },
    });

    const levelByRuleId = Object.fromEntries(
      sarif.runs[0]!.results.map((result) => [result.ruleId, result.level]),
    );

    expect(levelByRuleId['AU.APP.11.1.blocking-privacy-issue']).toBe('error');
    expect(levelByRuleId['AU.APP.11.1.unrelated-informational-issue']).toBe('note');
  });

  it('suppresses SARIF findings for PASS and emits note-level OUT_OF_SCOPE findings', async () => {
    const passSarif = await formatSarif({
      findings: [makeFinding()],
      jurisdiction: 'au-privacy-act',
      version: '0.4.0',
      deployDecision: {
        verdict: 'PASS',
        blocking: false,
        confidence: 0.8,
        jurisdiction: 'au-privacy-act',
        packValidationStatus: 'internal_validated',
        reasons: ['No in-scope blocking findings.'],
        evidenceRefs: [],
        remediations: [],
      },
    });

    expect(passSarif.runs[0]!.results).toEqual([]);
    expect(passSarif.runs[0]!.tool.driver.rules).toEqual([]);

    const outOfScopeSarif = await formatSarif({
      findings: [makeFinding()],
      jurisdiction: 'au-privacy-act',
      version: '0.4.0',
      deployDecision: {
        verdict: 'OUT_OF_SCOPE',
        blocking: false,
        confidence: 0.5,
        jurisdiction: 'au-privacy-act',
        packValidationStatus: 'internal_validated',
        reasons: ['Outside selected pack coverage.'],
        evidenceRefs: ['ev-chain:finding:finding-1'],
        remediations: [],
      },
    });

    expect(outOfScopeSarif.runs[0]!.results).toHaveLength(1);
    expect(outOfScopeSarif.runs[0]!.results[0]!.level).toBe('note');
    expect(outOfScopeSarif.runs[0]!.tool.driver.rules).toHaveLength(1);
    expect(outOfScopeSarif.runs[0]!.tool.driver.rules[0]!.properties['problem.severity']).toBe('recommendation');
  });

  it('formats rule ID prefixes for supported jurisdictions', () => {
    expect(buildJurisdictionQualifiedRuleId('au-privacy-act', 'APP_11', 'Policy Accessible')).toBe('AU.APP.11.1.policy-accessible');
    expect(buildJurisdictionQualifiedRuleId('us-ccpa', 'CCPA_100', 'Disclosure')).toBe('US.CCPA.1798.100.disclosure');
    expect(buildJurisdictionQualifiedRuleId('eu-gdpr', 'GDPR_Art13', 'Privacy Notice')).toBe('EU.GDPR.ART.13.privacy-notice');
  });
});
