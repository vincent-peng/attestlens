import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  OSV_QUERY_BATCH_URL,
  OSV_VULN_URL,
  scanOsvVulnerabilities,
  type FetchLike,
} from './osv.js';

describe('scanOsvVulnerabilities', () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-osv-'));
    await fs.writeFile(path.join(tmpDir, 'package-lock.json'), '{}');
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('returns no findings for an empty OSV result', async () => {
    const fetchImpl: FetchLike = async () => jsonResponse({ results: [{}] });

    const result = await scanOsvVulnerabilities(
      [{ name: 'safe-package', version: '1.0.0' }],
      tmpDir,
      '0.2.0',
      { fetchImpl },
    );

    expect(result.findings).toEqual([]);
    expect(result.errors).toEqual([]);
  });

  it('queries batch results, fetches vulnerability details, and emits supply-chain findings', async () => {
    const calls: string[] = [];
    const fetchImpl: FetchLike = async (input) => {
      const url = String(input);
      calls.push(url);
      if (url === OSV_QUERY_BATCH_URL) {
        return jsonResponse({
          results: [{
            vulns: [{ id: 'GHSA-test-1234', modified: '2026-04-01T00:00:00Z' }],
          }],
        });
      }
      if (url === `${OSV_VULN_URL}GHSA-test-1234`) {
        return jsonResponse({
          id: 'GHSA-test-1234',
          summary: 'Prototype pollution in vulnerable-package',
          aliases: ['CVE-2026-0001'],
          database_specific: { severity: 'HIGH' },
          affected: [{
            package: { ecosystem: 'npm', name: 'vulnerable-package' },
            ranges: [{ events: [{ introduced: '0' }, { fixed: '1.2.3' }] }],
          }],
          references: [{ type: 'ADVISORY', url: 'https://osv.dev/vulnerability/GHSA-test-1234' }],
        });
      }
      return jsonResponse({}, 404);
    };

    const result = await scanOsvVulnerabilities(
      [{ name: 'vulnerable-package', version: '1.0.0' }],
      tmpDir,
      '0.2.0',
      { fetchImpl },
    );

    expect(calls).toEqual([OSV_QUERY_BATCH_URL, `${OSV_VULN_URL}GHSA-test-1234`]);
    expect(result.errors).toEqual([]);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].source).toBe('supply-chain');
    expect(result.findings[0].sourceRule).toBe('VS-OSV-GHSA-test-1234');
    expect(result.findings[0].severity).toBe('high');
    expect(result.findings[0].fix).toContain('1.2.3');
    expect(result.findings[0].evidence.rawOutput).toMatchObject({
      source: 'osv.dev',
      vulnerabilityId: 'GHSA-test-1234',
      packageName: 'vulnerable-package',
      packageVersion: '1.0.0',
      fixedVersions: ['1.2.3'],
    });
  });

  it('skips invalid OSV vulnerability ids with a recoverable error', async () => {
    const fetchImpl: FetchLike = async () => jsonResponse({
      results: [{ vulns: [{ id: '<script>alert(1)</script>' }] }],
    });

    const result = await scanOsvVulnerabilities(
      [{ name: 'unsafe-package', version: '1.0.0' }],
      tmpDir,
      '0.2.0',
      { fetchImpl },
    );

    expect(result.findings).toEqual([]);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]).toMatchObject({
      source: 'supply-chain',
      code: 'OSV_INVALID_ID',
      recoverable: true,
    });
  });

  it('sanitizes untrusted OSV detail metadata before building findings', async () => {
    const fetchImpl: FetchLike = async (input) => {
      const url = String(input);
      if (url === OSV_QUERY_BATCH_URL) {
        return jsonResponse({
          results: [{ vulns: [{ id: 'GHSA-safe-5678' }] }],
        });
      }
      if (url === `${OSV_VULN_URL}GHSA-safe-5678`) {
        return jsonResponse({
          id: 'GHSA-safe-5678',
          summary: '\u001B[31m<img src=x onerror=alert(1)> Markdown **bold**',
          aliases: ['CVE-2026-0002', '<img onerror=alert(2)>'],
          database_specific: { severity: 'HIGH' },
          affected: [{
            package: { ecosystem: 'npm', name: 'unsafe-package' },
            ranges: [{ events: [{ introduced: '0' }, { fixed: '2.0.0<script>' }] }],
          }],
          references: [
            { type: 'ADVISORY', url: 'javascript:alert(1)' },
            { type: 'WEB', url: 'https://example.com/<unsafe>' },
          ],
        });
      }
      return jsonResponse({}, 404);
    };

    const result = await scanOsvVulnerabilities(
      [{ name: 'unsafe-package', version: '1.0.0' }],
      tmpDir,
      '0.2.0',
      { fetchImpl },
    );

    expect(result.errors).toEqual([]);
    expect(result.findings).toHaveLength(1);
    const finding = result.findings[0];
    expect(`${finding.title} ${finding.description} ${finding.fix}`).not.toMatch(/[<>\u001B]/);
    expect(finding.title).not.toContain('**bold**');
    expect(finding.title).toContain('\\*\\*bold\\*\\*');
    expect(finding.sourceRule).toBe('VS-OSV-GHSA-safe-5678');

    const raw = finding.evidence.rawOutput as {
      aliases: string[];
      fixedVersions: string[];
      references: string[];
    };
    expect(raw.aliases.join(' ')).not.toMatch(/[<>\u001B]/);
    expect(raw.fixedVersions.join(' ')).not.toMatch(/[<>\u001B]/);
    expect(raw.references).toEqual(['https://example.com/unsafe']);
  });

  it('returns a recoverable error when querybatch times out', async () => {
    const fetchImpl: FetchLike = (_input, init) => new Promise((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => {
        const error = new Error('aborted');
        error.name = 'AbortError';
        reject(error);
      });
    });

    const result = await scanOsvVulnerabilities(
      [{ name: 'vulnerable-package', version: '1.0.0' }],
      tmpDir,
      '0.2.0',
      { fetchImpl, timeoutMs: 1 },
    );

    expect(result.findings).toEqual([]);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]).toMatchObject({
      source: 'supply-chain',
      code: 'OSV_API_ERROR',
      recoverable: true,
    });
  });

  it('rejects oversized OSV responses before parsing JSON', async () => {
    const fetchImpl: FetchLike = async () => new Response('{"results":[]}', {
      status: 200,
      headers: { 'content-length': '100' },
    });

    const result = await scanOsvVulnerabilities(
      [{ name: 'vulnerable-package', version: '1.0.0' }],
      tmpDir,
      '0.2.0',
      { fetchImpl, maxBytes: 10 },
    );

    expect(result.findings).toEqual([]);
    expect(result.errors[0].code).toBe('OSV_API_ERROR');
    expect(result.errors[0].message).toContain('exceeds');
  });
});

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}
