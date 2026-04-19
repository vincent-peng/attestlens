import { describe, expect, it } from 'vitest';

import { ScanSource } from './index.js';

describe('ScanSource', () => {
  it('only exposes shipped scanner sources', () => {
    expect(ScanSource.options).toEqual([
      'guardvibe',
      'vibesafe',
      'mcp-scan',
      'vibe-check',
      'supply-chain',
      'url-scan',
      'manual',
      'questionnaire',
    ]);
    expect(ScanSource.options).not.toContain('shannon');
  });
});
