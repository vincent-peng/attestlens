import { describe, expect, it } from 'vitest';

import { SG_PDPA_CHECKS, scanSgPdpaChecks } from './sg-pdpa-checks.js';

describe('SG_PDPA_CHECKS', () => {
  it('exposes the expected SG PDPA rule ids', () => {
    expect(SG_PDPA_CHECKS.map((rule) => rule.id)).toEqual([
      'SGPDPA-CONSENT-001',
      'SGPDPA-PURPOSE-001',
      'SGPDPA-SEC-001',
    ]);
  });

  it('emits consent findings with SG PDPA regulation mappings', () => {
    const findings = scanSgPdpaChecks([
      { relativePath: 'src/app.tsx', content: 'export const App = () => <div>hello</div>;' },
    ], 'test');
    const finding = findings.find((candidate) => candidate.sourceRule === 'SGPDPA-CONSENT-001');

    expect(finding?.regulationMappings).toEqual([
      expect.objectContaining({
        jurisdiction: 'sg-pdpa',
        principle: 'SGPDPA_11',
      }),
    ]);
  });

  it('emits protection findings with SG PDPA regulation mappings', () => {
    const findings = scanSgPdpaChecks([
      { relativePath: 'data/customer.json', content: '{"nric":"S1234567D"}' },
    ], 'test');
    const finding = findings.find((candidate) => candidate.sourceRule === 'SGPDPA-SEC-001');

    expect(finding?.regulationMappings).toEqual([
      expect.objectContaining({
        jurisdiction: 'sg-pdpa',
        principle: 'SGPDPA_24',
      }),
    ]);
  });
});
