import type { AttestLensFinding } from '../schema/index.js';

export function calculateMappingConfidence(baseConfidence: number, finding: AttestLensFinding): number {
  let confidence = baseConfidence;
  const rawOutput = getRawOutput(finding);

  const typosquatDistance = getNumber(rawOutput.typosquatDistance);
  if (typosquatDistance !== undefined) {
    confidence *= 1 - (typosquatDistance * 0.15);
  }

  if (isAuthSensitiveUrlFinding(finding, rawOutput)) {
    confidence *= 1.15;
  }

  if (isTemplateEnvironmentFile(finding.file)) {
    confidence *= 0.8;
  }

  if (hasCorroboratedAdvisoryEvidence(rawOutput)) {
    confidence *= 1.1;
  }

  const corroboratingSourceCount = getCorroboratingSourceCount(finding, rawOutput);
  if (corroboratingSourceCount > 0) {
    confidence += Math.min(0.15, corroboratingSourceCount * 0.05);
  }

  return roundConfidence(Math.max(0.5, Math.min(1, confidence)));
}

function getRawOutput(finding: AttestLensFinding): Record<string, unknown> {
  return typeof finding.evidence.rawOutput === 'object' && finding.evidence.rawOutput !== null
    ? finding.evidence.rawOutput as Record<string, unknown>
    : {};
}

function getNumber(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

function isAuthSensitiveUrlFinding(
  finding: AttestLensFinding,
  rawOutput: Record<string, unknown>,
): boolean {
  if (finding.source !== 'url-scan') return false;
  if (finding.sourceRule !== 'AL-URL-001' && finding.sourceRule !== 'AL-URL-002') return false;

  const url = finding.url || (typeof rawOutput.url === 'string' ? rawOutput.url : undefined);
  if (!url) return false;

  try {
    const parsed = new URL(url);
    return /\/(?:login|auth|signin|sign-in|account|checkout|admin)(?:\/|$)/i.test(parsed.pathname);
  } catch {
    return /\/(?:login|auth|signin|sign-in|account|checkout|admin)(?:\/|$)/i.test(url);
  }
}

function isTemplateEnvironmentFile(file: string | undefined): boolean {
  if (!file) return false;
  const lower = file.toLowerCase();
  return (
    lower.includes('.env.example') ||
    lower.includes('.env.sample') ||
    lower.includes('.env.template') ||
    lower.endsWith('.example') ||
    lower.endsWith('.sample') ||
    lower.endsWith('.template')
  );
}

function hasCorroboratedAdvisoryEvidence(rawOutput: Record<string, unknown>): boolean {
  return Boolean(rawOutput.osvSourceRule || rawOutput.osv);
}

function getCorroboratingSourceCount(
  finding: AttestLensFinding,
  rawOutput: Record<string, unknown>,
): number {
  const topLevel = Array.isArray(finding.corroboratedBy) ? finding.corroboratedBy.length : 0;
  const raw = Array.isArray(rawOutput.corroboratedBy) ? rawOutput.corroboratedBy.length : 0;
  return Math.max(topLevel, raw);
}

function roundConfidence(confidence: number): number {
  return Math.round(confidence * 100) / 100;
}
