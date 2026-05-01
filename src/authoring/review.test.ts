import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { reviewPack } from './review.js';

describe('reviewPack', () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    await Promise.all(tempDirs.map((dir) => fs.rm(dir, { recursive: true, force: true })));
    tempDirs.length = 0;
  });

  async function makeTempDir(): Promise<string> {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-review-'));
    tempDirs.push(dir);
    return dir;
  }

  async function writeProposedPack(dir: string): Promise<string> {
    const proposedPath = path.join(dir, 'proposed.json');
    await fs.writeFile(proposedPath, JSON.stringify({
      schemaVersion: '3.0',
      jurisdiction: 'sg-pdpa',
      generatedAt: '2026-05-01T00:00:00.000Z',
      sourceDocumentHash: 'abc123',
      principles: [{
        id: 'SGPDPA_24',
        shortName: 'Protection',
        obligation: 'Protect personal data',
      }],
      rules: [
        {
          id: 'SGPDPA-SEC-001',
          category: 'guardvibe-static',
          severity: 'high',
          title: 'Detect hardcoded API keys',
          description: 'Avoid hardcoded keys',
          pattern: 'apiKey = [\'"]',
          addedIn: '2026.05.01',
          source: {
            jurisdiction: 'sg-pdpa',
            citation: 'PDPA Section 24',
          },
          authoring: {
            author: 'ai-draft',
            confidence: 'high',
            falsePositiveRisk: 'low',
          },
          provenance: {
            draftedByModel: 'gpt-5.5',
            draftedAt: '2026-05-01T00:00:00.000Z',
            draftingPromptVersion: 'phase-11-v1',
            sourceDocumentHash: 'abc123',
          },
          interpretation: {
            machineCheckable: true,
            determinism: 'deterministic',
            reviewRequired: true,
            falsePositiveRisk: 'low',
          },
          tests: {
            positive: [{ name: 'positive', input: 'const apiKey = "secret";', shouldTrigger: true }],
            negative: [],
            edgeCase: [],
          },
        },
        {
          id: 'SGPDPA-SEC-LOW',
          category: 'guardvibe-static',
          severity: 'medium',
          title: 'Low confidence rule',
          description: 'Needs work',
          pattern: 'token = [\'"]',
          addedIn: '2026.05.01',
          source: {
            jurisdiction: 'sg-pdpa',
            citation: 'PDPA Section 24',
          },
          authoring: {
            author: 'ai-draft',
            confidence: 'low',
            falsePositiveRisk: 'high',
          },
          provenance: {
            draftedByModel: 'gpt-5.5',
            draftedAt: '2026-05-01T00:00:00.000Z',
            draftingPromptVersion: 'phase-11-v1',
            sourceDocumentHash: 'abc123',
          },
          interpretation: {
            machineCheckable: true,
            determinism: 'heuristic',
            reviewRequired: true,
            falsePositiveRisk: 'high',
          },
          tests: {
            positive: [],
            negative: [],
            edgeCase: [],
          },
        },
      ],
      confidence: 'medium',
      warnings: [],
      gaps: [],
    }, null, 2));
    return proposedPath;
  }

  it('approves all rules and populates provenance', async () => {
    const dir = await makeTempDir();
    const manifest = await reviewPack({
      proposedPath: await writeProposedPack(dir),
      reviewer: 'alice',
      outputPath: path.join(dir, 'validated.json'),
      approveAll: true,
      now: new Date('2026-05-01T01:00:00.000Z'),
    });

    expect(manifest.schemaVersion).toBe('2.1');
    expect(manifest.rules).toHaveLength(2);
    expect(manifest.rules[0]?.authoring.author).toBe('human-validated');
    expect(manifest.rules[0]?.provenance.approvedBy).toBe('alice');
    expect(manifest.rules[0]?.interpretation.reviewRequired).toBe(false);
  });

  it('rejects low-confidence rules when configured', async () => {
    const dir = await makeTempDir();
    const manifest = await reviewPack({
      proposedPath: await writeProposedPack(dir),
      reviewer: 'alice',
      outputPath: path.join(dir, 'validated.json'),
      approveAll: true,
      rejectLowConfidence: true,
      now: new Date('2026-05-01T01:00:00.000Z'),
    });

    expect(manifest.rules).toHaveLength(1);
    expect(manifest.rules[0]?.id).toBe('SGPDPA-SEC-001');
    expect(manifest.ruleProvenance['SGPDPA-SEC-LOW']).toBeUndefined();
  });
});
