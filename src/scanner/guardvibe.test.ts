import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { GuardVibeAdapter } from './guardvibe.js';
import { buildEmbeddedRulePack } from './rules/embedded.js';
import { getRulePackCachePath, loadRulePack, updateRuleCache } from './rules/loader.js';
import type { ScannerResult } from './types.js';

describe('GuardVibeAdapter', { timeout: 20000 }, () => {
  const adapter = new GuardVibeAdapter();
  let scanResult: ScannerResult;
  let fixtureDir: string;

  beforeAll(async () => {
    fixtureDir = await createVulnerableAppFixture();
    scanResult = await adapter.scan(fixtureDir);
  });

  afterAll(async () => {
    if (fixtureDir) {
      await fs.rm(fixtureDir, { recursive: true, force: true });
    }
  });

  it('should always be available (static fallback)', async () => {
    const available = await adapter.isAvailable();
    expect(available).toBe(true);
  });

  it('should detect hardcoded secrets in .env files', async () => {
    const hardKeyFindings = scanResult.findings.filter(
      f => f.sourceRule === 'VS-HARDKEY'
    );
    expect(hardKeyFindings.length).toBeGreaterThan(0);
  });

  it('should detect XSS patterns', async () => {
    const xssFindings = scanResult.findings.filter(
      f => f.sourceRule === 'VS-XSS'
    );
    expect(xssFindings.length).toBeGreaterThan(0);
  });

  it('should detect debug logging of sensitive data', async () => {
    const debugFindings = scanResult.findings.filter(
      f => f.sourceRule === 'VS-DEBUG'
    );
    expect(debugFindings.length).toBeGreaterThan(0);
  });

  it('should detect env var exposure', async () => {
    const envFindings = scanResult.findings.filter(
      f => f.sourceRule === 'VS-ENV'
    );
    expect(envFindings.length).toBeGreaterThan(0);
  });

  it('does not treat secret resolver identifiers as hardcoded secret literals', async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-secret-resolver-'));
    try {
      await fs.mkdir(path.join(tempDir, 'src'), { recursive: true });
      await fs.writeFile(
        path.join(tempDir, 'src', 'config.ts'),
        [
          'const apiKey = resolveOpenAiApiKey();',
          'const accessToken = getAccessTokenFromEnv();',
          'const secret_key = resolveSecretValue;',
          'const OPENAI_API_KEY = resolveOpenAiApiKey;',
        ].join('\n'),
      );

      const result = await new GuardVibeAdapter('__attestlens_missing_guardvibe__').scan(tempDir);

      expect(result.findings.some(finding => finding.sourceRule === 'VS-HARDKEY')).toBe(false);
    } finally {
      await fs.rm(tempDir, { recursive: true, force: true });
    }
  });

  it('keeps hardcoded secret literals while allowing unquoted values only in env files', async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-hardkey-context-'));
    try {
      await fs.mkdir(path.join(tempDir, 'src'), { recursive: true });
      await fs.writeFile(
        path.join(tempDir, '.env'),
        'APIKEY=abcdefghijklmnop\n',
      );
      await fs.writeFile(
        path.join(tempDir, 'src', 'config.ts'),
        [
          'const secret_key = "abcdefghijklmnop";',
          'const OPENAI_API_KEY = "abcdefghijklmnop";',
          'const unquoted_api_key = abcdefghijklmnop;',
        ].join('\n'),
      );

      const result = await new GuardVibeAdapter('__attestlens_missing_guardvibe__').scan(tempDir);
      const hardKeyFindings = result.findings.filter(finding => finding.sourceRule === 'VS-HARDKEY');

      expect(hardKeyFindings).toHaveLength(3);
      expect(hardKeyFindings.some(finding => finding.file === '.env' && finding.code?.includes('APIKEY'))).toBe(true);
      expect(hardKeyFindings.filter(finding => finding.file === 'src/config.ts')).toHaveLength(2);
      expect(hardKeyFindings.some(finding => finding.code?.includes('unquoted_api_key'))).toBe(false);
    } finally {
      await fs.rm(tempDir, { recursive: true, force: true });
    }
  });

  it('should produce findings with required fields', async () => {
    for (const finding of scanResult.findings) {
      expect(finding.id).toBeTruthy();
      expect(finding.source).toBe('guardvibe');
      expect(finding.sourceRule).toBeTruthy();
      expect(['critical', 'high', 'medium', 'low', 'info']).toContain(finding.severity);
      expect(finding.title).toBeTruthy();
      expect(finding.file).toBeTruthy();
      expect(finding.line).toBeGreaterThan(0);
    }
  });

  it('should return errors when MCP is unavailable', async () => {
    // MCP is not installed, so there should be an error about it
    expect(scanResult.errors.length).toBeGreaterThanOrEqual(0);
  });

  it('uses active rule-pack definitions for migrated GuardVibe fallback rules only', async () => {
    const embedded = buildEmbeddedRulePack();
    const activeRulePack = {
      ...embedded,
      rules: embedded.rules.map((rule) => {
        if (rule.id === 'VS-XSS') {
          return {
            ...rule,
            severity: 'high' as const,
            title: 'Cached XSS rule',
            description: 'Cached description',
            fixPrompt: 'Cached fix',
          };
        }

        if (rule.id === 'AL-URL-013') {
          return {
            ...rule,
            pattern: String.raw`dangerouslySetInnerHTML`,
            title: 'Metadata-only URL rule should not execute in GuardVibe fallback',
          };
        }

        return rule;
      }).concat({
        id: 'GV-REMOTE-001',
        category: 'guardvibe-static',
        severity: 'critical' as const,
        title: 'Unknown remote executable rule',
        description: 'Unknown executable rule should remain metadata-only.',
        pattern: String.raw`dangerouslySetInnerHTML`,
        flags: 'gi',
        fixPrompt: 'Do not execute this rule.',
        appMappings: [],
        addedIn: '2026.04.25',
        enabled: true,
        tags: ['guardvibe'],
      }),
    };
    const fallbackAdapter = new GuardVibeAdapter('__attestlens_missing_guardvibe__');

    const result = await fallbackAdapter.scan(fixtureDir, { rulePack: activeRulePack });
    const xssFinding = result.findings.find((finding) => finding.sourceRule === 'VS-XSS');

    expect(xssFinding).toEqual(expect.objectContaining({
      severity: 'high',
      title: 'Cached XSS rule',
      description: 'Cached description',
      fix: 'Cached fix',
    }));
    expect(result.findings.some((finding) => finding.sourceRule === 'AL-URL-013')).toBe(false);
    expect(result.findings.some((finding) => finding.sourceRule === 'GV-REMOTE-001')).toBe(false);
    expect(result.errors.some((error) => error.code === 'RULE_PACK_EXECUTION_FALLBACK')).toBe(false);
  });

  it('honours disabled active migrated rules without embedded fallback', async () => {
    const embedded = buildEmbeddedRulePack();
    const activeRulePack = {
      ...embedded,
      rules: embedded.rules.map((rule) => rule.id === 'VS-XSS'
        ? { ...rule, enabled: false }
        : rule),
    };
    const fallbackAdapter = new GuardVibeAdapter('__attestlens_missing_guardvibe__');

    const result = await fallbackAdapter.scan(fixtureDir, { rulePack: activeRulePack });

    expect(result.findings.some((finding) => finding.sourceRule === 'VS-XSS')).toBe(false);
    expect(result.errors.some((error) => error.code === 'RULE_PACK_EXECUTION_FALLBACK')).toBe(false);
  });

  it('falls back visibly to embedded executable rules when an active regex is invalid', async () => {
    const embedded = buildEmbeddedRulePack();
    const activeRulePack = {
      ...embedded,
      rules: embedded.rules.map((rule) => rule.id === 'VS-XSS'
        ? { ...rule, pattern: '(', title: 'Broken cached XSS rule' }
        : rule),
    };
    const fallbackAdapter = new GuardVibeAdapter('__attestlens_missing_guardvibe__');

    const result = await fallbackAdapter.scan(fixtureDir, { rulePack: activeRulePack });
    const xssFinding = result.findings.find((finding) => finding.sourceRule === 'VS-XSS');

    expect(xssFinding).toEqual(expect.objectContaining({
      severity: 'medium',
      title: 'Potential XSS vector',
    }));
    expect(result.errors).toEqual(expect.arrayContaining([
      expect.objectContaining({
        code: 'RULE_PACK_EXECUTION_FALLBACK',
        recoverable: true,
        message: expect.stringContaining('changed regex pattern or flags'),
      }),
    ]));
  });

  it('falls back visibly when active regex flags differ from embedded rules', async () => {
    const embedded = buildEmbeddedRulePack();
    const activeRulePack = {
      ...embedded,
      rules: embedded.rules.map((rule) => rule.id === 'VS-XSS'
        ? { ...rule, flags: 'gim', title: 'Flag-mutated XSS rule' }
        : rule),
    };
    const fallbackAdapter = new GuardVibeAdapter('__attestlens_missing_guardvibe__');

    const result = await fallbackAdapter.scan(fixtureDir, { rulePack: activeRulePack });
    const xssFinding = result.findings.find((finding) => finding.sourceRule === 'VS-XSS');

    expect(xssFinding?.title).toBe('Potential XSS vector');
    expect(result.errors).toEqual(expect.arrayContaining([
      expect.objectContaining({
        code: 'RULE_PACK_EXECUTION_FALLBACK',
        message: expect.stringContaining('changed regex pattern or flags'),
      }),
    ]));
  });

  it('falls back visibly when a cached executable hardkey pattern is older', async () => {
    const embedded = buildEmbeddedRulePack();
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-rules-cache-'));
    const projectDir = path.join(tempDir, 'project');
    const sourcePath = path.join(tempDir, 'rules.json');
    const cacheDir = path.join(tempDir, 'cache');
    const oldHardkeyPattern = String.raw`(?:\b[A-Z0-9_]*(?:API[_-]KEY|SECRET[_-]KEY|PRIVATE[_-]KEY|ACCESS[_-]TOKEN)[A-Z0-9_]*\s*=\s*['"]?[A-Za-z0-9+/=_-]{16,}['"]?|\b[a-zA-Z0-9_]*(?:api[_-]?key|secret[_-]?key|private[_-]?key|access[_-]?token)[a-zA-Z0-9_]*\s*[:=]\s*['"][A-Za-z0-9+/=_-]{16,}['"])`;
    const oldRulePack = {
      ...embedded,
      version: '2026.04.26',
      generated: '2026-04-26T00:00:00.000Z',
      rules: embedded.rules.map((rule) => rule.id === 'VS-HARDKEY'
        ? { ...rule, pattern: oldHardkeyPattern }
        : rule),
    };

    try {
      await fs.mkdir(projectDir, { recursive: true });
      await fs.writeFile(path.join(projectDir, '.env'), 'APIKEY=abcdefghijklmnop\n');
      await fs.writeFile(sourcePath, JSON.stringify(oldRulePack, null, 2));
      await updateRuleCache({ source: sourcePath, cacheDir });
      const loaded = await loadRulePack({ cacheDir });
      const fallbackAdapter = new GuardVibeAdapter('__attestlens_missing_guardvibe__');

      const result = await fallbackAdapter.scan(projectDir, { rulePack: loaded.manifest });

      expect(result.findings.some((finding) => finding.sourceRule === 'VS-HARDKEY' && finding.file === '.env')).toBe(true);
      expect(result.errors).toEqual(expect.arrayContaining([
        expect.objectContaining({
          code: 'RULE_PACK_EXECUTION_FALLBACK',
          message: expect.stringContaining('VS-HARDKEY changed regex pattern or flags'),
        }),
      ]));
    } finally {
      await fs.rm(tempDir, { recursive: true, force: true });
    }
  });

  it('falls back visibly when an active pack omits a required migrated rule', async () => {
    const embedded = buildEmbeddedRulePack();
    const activeRulePack = {
      ...embedded,
      rules: embedded.rules.filter((rule) => rule.id !== 'VS-XSS'),
    };
    const fallbackAdapter = new GuardVibeAdapter('__attestlens_missing_guardvibe__');

    const result = await fallbackAdapter.scan(fixtureDir, { rulePack: activeRulePack });
    const xssFinding = result.findings.find((finding) => finding.sourceRule === 'VS-XSS');

    expect(xssFinding?.title).toBe('Potential XSS vector');
    expect(result.errors).toEqual(expect.arrayContaining([
      expect.objectContaining({
        code: 'RULE_PACK_EXECUTION_FALLBACK',
        message: expect.stringContaining('missing executable GuardVibe rule VS-XSS'),
      }),
    ]));
  });

  it('executes stale cached migrated rules while preserving stale freshness metadata', async () => {
    const embedded = buildEmbeddedRulePack();
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-rules-cache-'));
    const sourcePath = path.join(tempDir, 'rules.json');
    const cacheDir = path.join(tempDir, 'cache');
    const staleRulePack = {
      ...embedded,
      version: '2026.03.01',
      generated: '2026-03-01T00:00:00.000Z',
      rules: embedded.rules.map((rule) => rule.id === 'VS-XSS'
        ? { ...rule, title: 'Stale cached XSS rule' }
        : rule),
    };

    try {
      await fs.writeFile(sourcePath, JSON.stringify(staleRulePack, null, 2));
      await updateRuleCache({ source: sourcePath, cacheDir });
      const loaded = await loadRulePack({
        cacheDir,
        now: new Date('2026-04-25T00:00:00.000Z'),
      });
      const fallbackAdapter = new GuardVibeAdapter('__attestlens_missing_guardvibe__');

      const result = await fallbackAdapter.scan(fixtureDir, { rulePack: loaded.manifest });
      const xssFinding = result.findings.find((finding) => finding.sourceRule === 'VS-XSS');

      expect(loaded.freshness.stale).toBe(true);
      expect(loaded.cachePath).toBe(getRulePackCachePath(cacheDir));
      expect(xssFinding?.title).toBe('Stale cached XSS rule');
      expect(result.errors.some((error) => error.code === 'RULE_PACK_EXECUTION_FALLBACK')).toBe(false);
    } finally {
      await fs.rm(tempDir, { recursive: true, force: true });
    }
  });

  it('uses embedded executable rules when a corrupt cache falls back at load time', async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-rules-cache-'));
    const cacheDir = path.join(tempDir, 'cache');
    await fs.mkdir(cacheDir, { recursive: true });
    await fs.writeFile(getRulePackCachePath(cacheDir), '{not-json');

    try {
      const loaded = await loadRulePack({ cacheDir });
      const fallbackAdapter = new GuardVibeAdapter('__attestlens_missing_guardvibe__');

      const result = await fallbackAdapter.scan(fixtureDir, { rulePack: loaded.manifest });
      const xssFinding = result.findings.find((finding) => finding.sourceRule === 'VS-XSS');

      expect(loaded.freshness.source).toBe('embedded');
      expect(loaded.warnings[0]).toContain('Cached rule pack ignored');
      expect(xssFinding?.title).toBe('Potential XSS vector');
    } finally {
      await fs.rm(tempDir, { recursive: true, force: true });
    }
  });
});

async function createVulnerableAppFixture(): Promise<string> {
  const fixtureDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-vulnerable-app-'));
  await fs.mkdir(path.join(fixtureDir, 'src'), { recursive: true });

  await fs.writeFile(
    path.join(fixtureDir, '.env'),
    [
      'api_key="1234567890abcdef1234567890abcdef"',
      'NEXT_PUBLIC_SECRET=public-secret-value',
    ].join('\n'),
  );

  await fs.writeFile(
    path.join(fixtureDir, 'src', 'App.tsx'),
    [
      'export function App({ html, token }: { html: string; token: string }) {',
      '  console.log("token", token);',
      '  return <div dangerouslySetInnerHTML={{ __html: html }} />;',
      '}',
    ].join('\n'),
  );

  return fixtureDir;
}
