import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { proposeRules } from './propose.js';

describe('proposeRules', () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    await Promise.all(tempDirs.map((dir) => fs.rm(dir, { recursive: true, force: true })));
    tempDirs.length = 0;
  });

  async function makeTempDir(): Promise<string> {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-propose-'));
    tempDirs.push(dir);
    return dir;
  }

  it('creates a proposed pack from two mocked LLM passes', async () => {
    const tempDir = await makeTempDir();
    const sourcePath = path.join(tempDir, 'law.txt');
    const outputPath = path.join(tempDir, 'proposed.json');
    await fs.writeFile(sourcePath, 'Section 24: protect personal data.');

    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({
        choices: [{
          message: {
            content: JSON.stringify({
              principles: [{
                id: 'SGPDPA_24',
                shortName: 'Protection',
                obligation: 'Protect personal data',
              }],
              warnings: ['Needs human review'],
              gaps: ['No retention text found'],
              confidence: 'medium',
            }),
          },
        }],
      })))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        choices: [{
          message: {
            content: JSON.stringify({
              schemaVersion: '3.0',
              jurisdiction: 'sg-pdpa',
              principles: [{
                id: 'SGPDPA_24',
                shortName: 'Protection',
                obligation: 'Protect personal data',
              }],
              rules: [{
                id: 'SGPDPA-SEC-TEST',
                category: 'guardvibe-static',
                severity: 'high',
                title: 'Detect hardcoded API keys',
                description: 'Avoid hardcoded keys',
                pattern: 'apiKey = [\'"]',
                addedIn: '2026.05.01',
                source: {
                  citation: 'PDPA Section 24',
                },
                authoring: {
                  confidence: 'high',
                  falsePositiveRisk: 'low',
                },
                interpretation: {
                  machineCheckable: true,
                  determinism: 'deterministic',
                  falsePositiveRisk: 'low',
                },
                tests: {
                  positive: [{ name: 'positive', input: 'const apiKey = "secret";', shouldTrigger: true }],
                },
              }],
              mappingRules: [],
              questions: [],
              confidence: 'high',
              warnings: [],
              gaps: [],
            }),
          },
        }],
      })));

    const manifest = await proposeRules({
      jurisdiction: 'sg-pdpa',
      sourcePath,
      sourceUrl: 'https://example.com/pdpa',
      outputPath,
      apiKey: 'secret-key',
      fetchImpl: fetchMock as unknown as typeof fetch,
      now: new Date('2026-05-01T00:00:00.000Z'),
    });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(manifest.schemaVersion).toBe('3.0');
    expect(manifest.rules[0]?.authoring.author).toBe('ai-draft');
    expect(manifest.rules[0]?.interpretation.reviewRequired).toBe(true);
    expect(manifest.rules[0]?.provenance.draftedByModel).toBe('gpt-5.5');
    expect(manifest.sourceDocumentHash).toHaveLength(64);
    expect(await fs.readFile(outputPath, 'utf-8')).toContain('"schemaVersion": "3.0"');
  });

  it('requires an API key', async () => {
    const tempDir = await makeTempDir();
    const sourcePath = path.join(tempDir, 'law.txt');
    await fs.writeFile(sourcePath, 'Section 24');

    await expect(proposeRules({
      jurisdiction: 'sg-pdpa',
      sourcePath,
      outputPath: path.join(tempDir, 'proposed.json'),
      apiKey: '',
      fetchImpl: vi.fn() as unknown as typeof fetch,
    })).rejects.toThrow(/API key/);
  });
});
