/**
 * AttestLens — OSV.dev helper
 *
 * Keeps OSV vulnerability lookup inside the supply-chain adapter surface.
 * Tests inject fetch; production uses global fetch when available.
 */

import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import type { AttestLensFinding, Severity } from '../schema/index.js';
import type { ScannerError } from './types.js';

export type FetchLike = (input: string | URL, init?: RequestInit) => Promise<Response>;

export const OSV_QUERY_BATCH_URL = 'https://api.osv.dev/v1/querybatch';
export const OSV_VULN_URL = 'https://api.osv.dev/v1/vulns/';
export const OSV_FETCH_TIMEOUT_MS = 10_000;
export const OSV_MAX_RESPONSE_BYTES = 1_000_000;
const OSV_MAX_DETAIL_FETCHES = 100;
const OSV_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$/;
const MAX_SUMMARY_LENGTH = 240;
const MAX_ALIAS_LENGTH = 80;
const MAX_VERSION_LENGTH = 80;
const MAX_URL_LENGTH = 500;

export interface OsvPackageQuery {
  name: string;
  version: string;
  ecosystem?: 'npm';
}

export interface OsvScanOptions {
  fetchImpl?: FetchLike;
  timeoutMs?: number;
  maxBytes?: number;
  signal?: AbortSignal;
}

export interface OsvScanResult {
  findings: AttestLensFinding[];
  errors: ScannerError[];
}

interface OsvQueryBatchResponse {
  results?: Array<{
    vulns?: Array<{
      id: string;
      modified?: string;
    }>;
  }>;
}

interface OsvReference {
  type?: string;
  url?: string;
}

interface OsvSeverity {
  type?: string;
  score?: string;
}

interface OsvRangeEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
}

interface OsvAffected {
  package?: {
    ecosystem?: string;
    name?: string;
  };
  ranges?: Array<{
    type?: string;
    events?: OsvRangeEvent[];
  }>;
  versions?: string[];
}

interface OsvVulnerabilityDetail {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  modified?: string;
  published?: string;
  severity?: OsvSeverity[];
  affected?: OsvAffected[];
  references?: OsvReference[];
  database_specific?: {
    severity?: string;
    [key: string]: unknown;
  };
}

interface OsvFindingSeed {
  vulnerabilityId: string;
  modified?: string;
  packageName: string;
  packageVersion: string;
}

export async function scanOsvVulnerabilities(
  packages: OsvPackageQuery[],
  targetPath: string,
  scannerVersion: string,
  options: OsvScanOptions = {},
): Promise<OsvScanResult> {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch?.bind(globalThis);
  const timeoutMs = options.timeoutMs ?? OSV_FETCH_TIMEOUT_MS;
  const maxBytes = options.maxBytes ?? OSV_MAX_RESPONSE_BYTES;

  if (packages.length === 0 || !fetchImpl) {
    return { findings: [], errors: [] };
  }

  let queryBatch: OsvQueryBatchResponse;
  try {
    queryBatch = await fetchJsonWithLimit<OsvQueryBatchResponse>(
      fetchImpl,
      OSV_QUERY_BATCH_URL,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          queries: packages.map((pkg) => ({
            package: {
              name: pkg.name,
              ecosystem: pkg.ecosystem ?? 'npm',
            },
            version: pkg.version,
          })),
        }),
      },
      timeoutMs,
      maxBytes,
      options.signal,
    );
  } catch (error) {
    return {
      findings: [],
      errors: [makeOsvError('OSV_API_ERROR', `OSV querybatch failed: ${errorMessage(error)}`)],
    };
  }

  if (!Array.isArray(queryBatch.results)) {
    return {
      findings: [],
      errors: [makeOsvError('OSV_API_ERROR', 'OSV querybatch returned a malformed response')],
    };
  }

  const seeds: OsvFindingSeed[] = [];
  const errors: ScannerError[] = [];
  for (let i = 0; i < queryBatch.results.length; i += 1) {
    const result = queryBatch.results[i];
    const pkg = packages[i];
    if (!pkg || !Array.isArray(result?.vulns)) continue;

    for (const vuln of result.vulns) {
      if (!vuln.id) continue;
      const vulnerabilityId = normalizeOsvId(vuln.id);
      if (!vulnerabilityId) {
        errors.push(makeOsvError('OSV_INVALID_ID', `OSV returned an invalid vulnerability id for ${pkg.name}`));
        continue;
      }
      seeds.push({
        vulnerabilityId,
        modified: vuln.modified,
        packageName: pkg.name,
        packageVersion: pkg.version,
      });
    }
  }

  if (seeds.length === 0) {
    return { findings: [], errors };
  }

  const detailIds = Array.from(new Set(seeds.map((seed) => seed.vulnerabilityId))).slice(0, OSV_MAX_DETAIL_FETCHES);
  const details = new Map<string, OsvVulnerabilityDetail>();

  await Promise.all(detailIds.map(async (id) => {
    try {
      const detail = await fetchJsonWithLimit<OsvVulnerabilityDetail>(
        fetchImpl,
        `${OSV_VULN_URL}${encodeURIComponent(id)}`,
        { method: 'GET' },
        timeoutMs,
        maxBytes,
        options.signal,
      );
      if (detail?.id) {
        details.set(id, detail);
      }
    } catch (error) {
      errors.push(makeOsvError('OSV_DETAIL_ERROR', `OSV vulnerability detail fetch failed for ${id}: ${errorMessage(error)}`));
    }
  }));

  const evidenceFile = await fs.access(path.join(targetPath, 'package-lock.json'))
    .then(() => path.join(targetPath, 'package-lock.json'))
    .catch(() => path.join(targetPath, 'package.json'));

  const findings = seeds.map((seed) => makeOsvFinding(
    seed,
    details.get(seed.vulnerabilityId),
    evidenceFile,
    scannerVersion,
  ));

  return { findings, errors };
}

export async function fetchJsonWithLimit<T>(
  fetchImpl: FetchLike,
  url: string,
  init: RequestInit,
  timeoutMs: number,
  maxBytes: number,
  signal?: AbortSignal,
): Promise<T> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  const abort = () => controller.abort();
  signal?.addEventListener('abort', abort, { once: true });

  try {
    const response = await fetchImpl(url, {
      ...init,
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const text = await readResponseTextWithLimit(response, maxBytes);
    return JSON.parse(text) as T;
  } catch (error) {
    if ((error as Error).name === 'AbortError') {
      throw new Error(`request timed out after ${timeoutMs}ms`);
    }
    throw error;
  } finally {
    clearTimeout(timeout);
    signal?.removeEventListener('abort', abort);
  }
}

async function readResponseTextWithLimit(response: Response, maxBytes: number): Promise<string> {
  const contentLength = response.headers.get('content-length');
  if (contentLength && Number.parseInt(contentLength, 10) > maxBytes) {
    throw new Error(`response exceeds ${maxBytes} bytes`);
  }

  if (!response.body) {
    const text = await response.text();
    if (Buffer.byteLength(text, 'utf8') > maxBytes) {
      throw new Error(`response exceeds ${maxBytes} bytes`);
    }
    return text;
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;

    totalBytes += value.byteLength;
    if (totalBytes > maxBytes) {
      await reader.cancel();
      throw new Error(`response exceeds ${maxBytes} bytes`);
    }
    chunks.push(value);
  }

  const combined = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(combined);
}

function makeOsvFinding(
  seed: OsvFindingSeed,
  detail: OsvVulnerabilityDetail | undefined,
  file: string,
  scannerVersion: string,
): AttestLensFinding {
  const aliases = (detail?.aliases ?? [])
    .map((alias) => sanitizeDisplayText(alias, MAX_ALIAS_LENGTH))
    .filter(Boolean);
  const references = (detail?.references ?? [])
    .map((reference) => reference.url)
    .map((url) => sanitizeUrl(url))
    .filter((url): url is string => Boolean(url));
  const fixedVersions = getFixedVersions(detail, seed.packageName);
  const packageName = sanitizeText(seed.packageName, MAX_ALIAS_LENGTH);
  const packageVersion = sanitizeText(seed.packageVersion, MAX_VERSION_LENGTH);
  const summary = sanitizeDisplayText(detail?.summary || `OSV vulnerability ${seed.vulnerabilityId}`, MAX_SUMMARY_LENGTH);
  const aliasText = aliases.length > 0 ? ` Aliases: ${aliases.join(', ')}.` : '';
  const fixedText = fixedVersions.length > 0 ? ` Fixed version(s): ${fixedVersions.join(', ')}.` : '';

  return {
    id: generateOsvFindingId(seed, file),
    source: 'supply-chain',
    sourceRule: `VS-OSV-${seed.vulnerabilityId}`,
    severity: mapOsvSeverity(detail),
    category: 'Security',
    title: `OSV vulnerability in "${packageName}": ${summary}`,
    description: `OSV reports ${seed.vulnerabilityId} for "${packageName}" at version ${packageVersion}.${aliasText}${fixedText}`,
    file: path.isAbsolute(file) ? path.relative(process.cwd(), file) : file,
    line: undefined,
    code: undefined,
    fix: fixedVersions.length > 0
      ? `Upgrade "${packageName}" to a fixed version: ${fixedVersions.join(', ')}.`
      : `Review OSV advisory ${seed.vulnerabilityId} and update "${packageName}" to a patched version.`,
    regulationMappings: [],
    appMappings: [],
    evidence: {
      timestamp: new Date().toISOString(),
      scannerVersion,
      rawOutput: {
        source: 'osv.dev',
        vulnerabilityId: seed.vulnerabilityId,
        aliases,
        modified: detail?.modified ?? seed.modified,
        published: detail?.published,
        packageName,
        packageVersion,
        fixedVersions,
        references,
        detailAvailable: Boolean(detail),
      },
      scannerCommand: 'attestlens supply-chain-scan',
    },
  };
}

function getFixedVersions(detail: OsvVulnerabilityDetail | undefined, packageName: string): string[] {
  const versions = new Set<string>();
  for (const affected of detail?.affected ?? []) {
    const affectedName = affected.package?.name;
    if (affectedName && affectedName !== packageName) continue;

    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed) {
          const version = sanitizeDisplayText(event.fixed, MAX_VERSION_LENGTH);
          if (version) {
            versions.add(version);
          }
        }
      }
    }
  }
  return Array.from(versions).sort(compareVersionLike);
}

function mapOsvSeverity(detail: OsvVulnerabilityDetail | undefined): Severity {
  const candidates: Severity[] = [];
  const databaseSeverity = detail?.database_specific?.severity?.toLowerCase();
  const mappedDatabaseSeverity = databaseSeverity ? mapSeverityLabel(databaseSeverity) : null;
  if (mappedDatabaseSeverity) {
    candidates.push(mappedDatabaseSeverity);
  }

  for (const severity of detail?.severity ?? []) {
    const score = severity.score ?? '';
    const numeric = Number.parseFloat(score);
    if (Number.isFinite(numeric)) {
      candidates.push(mapNumericCvssScore(numeric));
      continue;
    }

    const cvssScore = parseCvssV3Vector(score);
    if (cvssScore !== null) {
      candidates.push(mapNumericCvssScore(cvssScore));
    }
  }

  if (candidates.length === 0) {
    return 'medium';
  }

  return candidates.reduce((highest, severity) => (
    SEVERITY_RANK[severity] > SEVERITY_RANK[highest] ? severity : highest
  ));
}

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

function mapSeverityLabel(label: string): Severity | null {
  if (label.includes('critical')) return 'critical';
  if (label.includes('high')) return 'high';
  if (label.includes('moderate') || label.includes('medium')) return 'medium';
  if (label.includes('low')) return 'low';
  return null;
}

function mapNumericCvssScore(score: number): Severity {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

function parseCvssV3Vector(vector: string): number | null {
  const trimmed = vector.trim().toUpperCase();
  if (!trimmed.startsWith('CVSS:3.0/') && !trimmed.startsWith('CVSS:3.1/')) {
    return null;
  }

  const metrics = new Map<string, string>();
  for (const segment of trimmed.split('/').slice(1)) {
    const [key, value] = segment.split(':');
    if (key && value) {
      metrics.set(key, value);
    }
  }

  const scope = metrics.get('S');
  if (scope !== 'U' && scope !== 'C') return null;

  const av = lookupMetric(metrics, 'AV', { N: 0.85, A: 0.62, L: 0.55, P: 0.2 });
  const ac = lookupMetric(metrics, 'AC', { L: 0.77, H: 0.44 });
  const ui = lookupMetric(metrics, 'UI', { N: 0.85, R: 0.62 });
  const c = lookupMetric(metrics, 'C', { H: 0.56, L: 0.22, N: 0 });
  const i = lookupMetric(metrics, 'I', { H: 0.56, L: 0.22, N: 0 });
  const a = lookupMetric(metrics, 'A', { H: 0.56, L: 0.22, N: 0 });
  const pr = lookupMetric(metrics, 'PR', scope === 'C'
    ? { N: 0.85, L: 0.68, H: 0.5 }
    : { N: 0.85, L: 0.62, H: 0.27 });

  if ([av, ac, ui, c, i, a, pr].some((value) => value === null)) {
    return null;
  }

  const impactSubScore = 1 - ((1 - c!) * (1 - i!) * (1 - a!));
  const impact = scope === 'C'
    ? 7.52 * (impactSubScore - 0.029) - 3.25 * Math.pow(impactSubScore - 0.02, 15)
    : 6.42 * impactSubScore;
  if (impact <= 0) return 0;

  const exploitability = 8.22 * av! * ac! * pr! * ui!;
  const rawScore = scope === 'C'
    ? Math.min(1.08 * (impact + exploitability), 10)
    : Math.min(impact + exploitability, 10);
  return roundUpCvss(rawScore);
}

function lookupMetric(
  metrics: Map<string, string>,
  key: string,
  weights: Record<string, number>,
): number | null {
  const value = metrics.get(key);
  return value && value in weights ? weights[value] : null;
}

function roundUpCvss(score: number): number {
  return Math.ceil((score - Number.EPSILON) * 10) / 10;
}

function makeOsvError(code: string, message: string): ScannerError {
  return {
    source: 'supply-chain',
    code,
    message: sanitizeText(message, 240),
    recoverable: true,
  };
}

function generateOsvFindingId(seed: OsvFindingSeed, file: string): string {
  const payload = `supply-chain:VS-OSV-${seed.vulnerabilityId}:${seed.packageName}:${seed.packageVersion}:${file}`;
  return crypto.createHash('sha256').update(payload).digest('hex').substring(0, 12);
}

function compareVersionLike(a: string, b: string): number {
  return a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' });
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function normalizeOsvId(value: string): string | null {
  const normalized = sanitizeText(value, 128);
  return OSV_ID_PATTERN.test(normalized) ? normalized : null;
}

function sanitizeUrl(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const sanitized = sanitizeText(value, MAX_URL_LENGTH);
  try {
    const url = new URL(sanitized);
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.toString() : null;
  } catch {
    return null;
  }
}

function sanitizeText(value: unknown, maxLength: number): string {
  if (typeof value !== 'string') return '';
  return value
    .replace(/\x1B\[[0-?]*[ -/]*[@-~]/g, '')
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
    .replace(/[<>]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, maxLength);
}

function sanitizeDisplayText(value: unknown, maxLength: number): string {
  return escapeMarkdownText(sanitizeText(value, maxLength)).slice(0, maxLength);
}

function escapeMarkdownText(value: string): string {
  return value.replace(/([\\`*_{}\[\]()#+!|])/g, '\\$1');
}
