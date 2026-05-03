#!/usr/bin/env node
/**
 * AttestLens — MCP Server
 *
 * Exposes AttestLens as an MCP server so AI editors (Cursor, Windsurf, etc.)
 * can run compliance scans directly.
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  ErrorCode,
  ListResourcesRequestSchema as ResourcesListSchema,
  McpError,
  ReadResourceRequestSchema as ResourcesReadSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';

import { mapAllFindings } from '../mapping/engine.js';
import {
  buildComplianceReport,
  generateAgentReport,
  generateHTMLReport,
  generateJSONReport,
  generateMarkdownReport,
  generatePDFReport,
} from '../report/generator.js';
import { buildSMBComplianceResult } from '../report/smb-generator.js';
import type { ComplianceReportWithSMB, ReportFormat, ReportOptions } from '../report/generator.js';
import { ScannerOrchestrator, type ScannerOrchestratorOptions } from '../scanner/orchestrator.js';
import type { ScannerError, ScannerResult } from '../scanner/types.js';
import { getRegistry } from '../jurisdiction/registry.js';
import {
  APPInfo,
  APPPrinciple as APPPrincipleSchema,
  ComplianceOpinion as ComplianceOpinionSchema,
  ControlStatus,
  DeployDecision as DeployDecisionSchema,
  Jurisdiction,
  JurisdictionCoverage as JurisdictionCoverageSchema,
  PackValidation as PackValidationSchema,
  RegulationPrinciple,
  RuleFreshness as RuleFreshnessSchema,
  ScanSource,
  Severity,
  reformImpactAssessmentSchema,
} from '../schema/index.js';
import type { APPPrinciple, AttestLensFinding, DiffContext, Jurisdiction as JurisdictionType, ReformImpactAssessment } from '../schema/index.js';
import { sanitizeTargetPathForOutput, sanitizeTargetUrlForOutput } from '../utils/target.js';
import { buildDiffContext } from '../git/diff.js';
import { ATTESTLENS_VERSION } from '../version.js';

type ToolResponse = {
  content: Array<{ type: 'text'; text: string }>;
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
};
type ToolErrorResponse = ToolResponse & { isError: true };
type ToolCallExtra = {
  signal?: AbortSignal;
};
type AllowedRootResource = {
  name: string;
  description: string;
  path: string;
};
type ListedAllowedRootResource = AllowedRootResource & {
  uri: string;
};
type SanitizedScannerError = {
  source: ScannerError['source'];
  message: string;
  code?: string;
  recoverable: boolean;
};

const LOCAL_READ_ONLY_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

const URL_READ_ONLY_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;

export const TOOL_DEFINITIONS = [
  {
    name: 'attestlens_scan',
    title: 'Project Compliance Scan',
    description: 'Scan a project directory for privacy compliance findings across supported jurisdictions.',
    annotations: URL_READ_ONLY_ANNOTATIONS,
  },
  {
    name: 'attestlens_scan_url',
    title: 'Live Site Compliance Scan',
    description: 'Scan a public URL for live-site APP/NDB compliance findings.',
    annotations: URL_READ_ONLY_ANNOTATIONS,
  },
  {
    name: 'attestlens_audit',
    title: 'Full Compliance Audit',
    description: 'Full compliance audit. Scans a project, maps findings to supported jurisdiction obligations, and generates a compliance report.',
    annotations: URL_READ_ONLY_ANNOTATIONS,
  },
  {
    name: 'attestlens_map',
    title: 'Map Findings to Regulation Controls',
    description: 'Map a list of security findings to supported jurisdiction obligations.',
    annotations: LOCAL_READ_ONLY_ANNOTATIONS,
  },
  {
    name: 'attestlens_opinion',
    title: 'Compliance Opinion',
    description: 'Generate a compliance opinion for a project. Returns a definitive verdict (COMPLIANT / PARTIALLY_COMPLIANT / NON_COMPLIANT) with per-principle assessments, confidence levels, and evidence chains. Deterministic — no LLM calls.',
    annotations: LOCAL_READ_ONLY_ANNOTATIONS,
  },
  {
    name: 'attestlens_check',
    title: 'Single Principle Compliance Check',
    description: 'Check a single regulation principle. Runs a full compliance scan and returns { principle, verdict, score, findings, remediations }.',
    annotations: LOCAL_READ_ONLY_ANNOTATIONS,
  },
  {
    name: 'attestlens_compliance_check',
    title: 'Compliance Check for Australian Businesses',
    description: 'Run a plain-English compliance check for Australian businesses. Scans a project for Privacy Act (APP/NDB) obligations and returns a readiness score, priority actions, compliance gaps, and reform warnings. Non-interactive: always scan-only without questionnaire.',
    annotations: LOCAL_READ_ONLY_ANNOTATIONS,
  },
  {
    name: 'attestlens_reform',
    title: 'Privacy Act Reform Impact Assessment',
    description: 'Run a Privacy Act 2026 reform impact assessment. Scans the project for reform-relevant patterns (statutory tort, children\'s privacy code, automated decision-making, AML/CTF) and returns a structured impact assessment with per-provision status, action items with deadlines, and overall impact rating.',
    annotations: LOCAL_READ_ONLY_ANNOTATIONS,
  },
] as const;

const MAX_SCANNER_TIMEOUT_MS = 300_000;

const scannerTimeoutMsInputSchema = z.number()
  .int()
  .positive()
  .max(MAX_SCANNER_TIMEOUT_MS)
  .describe('Per-scanner timeout in milliseconds')
  .optional();

const jurisdictionInputSchema = Jurisdiction
  .describe('Jurisdiction to check against')
  .default('au-privacy-act');

const pathScanOptionsInputSchema = {
  jurisdiction: jurisdictionInputSchema,
  strict: z.boolean().describe('Treat UNKNOWN controls as FAIL').default(false),
  externalEnrichment: z.boolean().describe('Enable external OSV.dev and npm registry dependency enrichment').default(false),
  includeTyposquat: z.boolean().describe('Enable experimental typosquatting detection (VS-SC-004)').default(false),
  behavioral: z.boolean().describe('Enable behavioral supply-chain analysis').default(true),
  iac: z.boolean().describe('Enable infrastructure-as-code misconfiguration scanning').default(true),
  includeGitleaks: z.boolean().describe('Enable opt-in git history secret scanning via gitleaks').default(false),
  scannerTimeoutMs: scannerTimeoutMsInputSchema,
  diffBase: z.string().describe('Git base ref for PR diff mode').optional(),
  diffHead: z.string().describe('Git head ref for PR diff mode').optional(),
  changedFiles: z.array(z.string()).describe('Changed files for PR diff mode when refs are resolved by the caller').optional(),
  changedFilesOnly: z.boolean().describe('Restrict feasible file-based findings to changed files').default(false),
};

const scanInputSchema = {
  path: z.string().describe('Path to the project directory to scan'),
  ...pathScanOptionsInputSchema,
};

const scanUrlInputSchema = {
  url: z.string().describe('Public http(s) URL to scan'),
  jurisdiction: jurisdictionInputSchema,
  strict: z.boolean().describe('Treat UNKNOWN controls as FAIL').default(false),
  scannerTimeoutMs: scannerTimeoutMsInputSchema,
};

const auditInputSchema = {
  path: z.string().describe('Path to the project directory to audit'),
  name: z.string().describe('Project name for the report').optional(),
  format: z.enum(['json', 'html', 'markdown', 'pdf', 'agent']).describe('Output format').default('json'),
  ...pathScanOptionsInputSchema,
  opinion: z.boolean().describe('Include compliance opinion in the audit result').default(false),
};

const mapInputSchema = {
  jurisdiction: jurisdictionInputSchema,
  findings: z.array(z.object({
    id: z.string().optional(),
    source: z.string(),
    sourceRule: z.string(),
    severity: z.string(),
    category: z.string().optional(),
    title: z.string(),
    description: z.string().optional(),
    file: z.string().optional(),
    line: z.number().optional(),
  }).passthrough()).describe('List of findings to map'),
};

const opinionInputSchema = {
  path: z.string().describe('Path to the project directory to audit'),
  jurisdiction: jurisdictionInputSchema,
  strict: z.boolean().describe('Treat UNKNOWN controls as NON_COMPLIANT').default(false),
};

const checkInputSchema = {
  path: z.string().describe('Path to the project directory'),
  jurisdiction: jurisdictionInputSchema,
  principle: RegulationPrinciple.describe('Regulation principle to check (e.g. APP_11)'),
  strict: z.boolean().describe('Treat UNKNOWN as NON_COMPLIANT').default(false),
};

const complianceCheckInputSchema = {
  path: z.string().describe('Path to the project directory to check'),
  jurisdiction: jurisdictionInputSchema,
  strict: z.boolean().describe('Treat unknown controls as failing').default(false),
  reform: z.boolean().describe('Include Privacy Act 2026 reform impact warnings').default(false),
};

const reformInputSchema = {
  path: z.string().describe('Path to the project directory to assess'),
  strict: z.boolean().describe('Treat UNKNOWN controls as FAIL').default(false),
};

const findingCountOutputSchema = z.object({
  critical: z.number().int().nonnegative(),
  high: z.number().int().nonnegative(),
  medium: z.number().int().nonnegative(),
  low: z.number().int().nonnegative(),
  info: z.number().int().nonnegative(),
});

const appMappingOutputSchema = z.object({
  principle: APPPrincipleSchema,
  obligation: z.string(),
  status: ControlStatus,
  confidence: z.number(),
});

const regulationMappingOutputSchema = z.object({
  jurisdiction: Jurisdiction,
  principle: RegulationPrinciple,
  obligation: z.string(),
  status: ControlStatus,
  confidence: z.number(),
  citation: z.string().optional(),
});

const serializedFindingOutputSchema = z.object({
  id: z.string(),
  source: ScanSource,
  sourceRule: z.string(),
  severity: Severity,
  title: z.string(),
  description: z.string(),
  file: z.string().optional(),
  line: z.number().optional(),
  url: z.string().optional(),
  fix: z.string().optional(),
  fixPrompt: z.string().optional(),
  corroboratedBy: z.array(ScanSource).optional(),
  introducedInDiff: z.boolean().optional(),
  regulationMappings: z.array(regulationMappingOutputSchema),
  appMappings: z.array(appMappingOutputSchema),
});

const diffContextOutputSchema = z.object({
  baseRef: z.string().optional(),
  headRef: z.string().optional(),
  changedFiles: z.array(z.string()),
  introducedFindings: z.array(z.string()),
  addedDependencies: z.array(z.string()),
  addedRoutes: z.array(z.string()),
});

const scannerErrorOutputSchema = z.object({
  source: z.string(),
  message: z.string(),
  code: z.string().optional(),
  recoverable: z.boolean().optional(),
}).passthrough();

const scanSummaryOutputSchema = {
  findings: z.array(serializedFindingOutputSchema),
  controls: z.array(z.object({
    jurisdiction: Jurisdiction,
    principle: RegulationPrinciple,
    shortName: z.string(),
    status: ControlStatus,
    score: z.number(),
  })),
  summary: z.object({
    total: z.number().int().nonnegative(),
    critical: z.number().int().nonnegative(),
    high: z.number().int().nonnegative(),
    medium: z.number().int().nonnegative(),
    low: z.number().int().nonnegative(),
    info: z.number().int().nonnegative(),
    affectedPrinciples: z.array(RegulationPrinciple),
    unmappedCount: z.number().int().nonnegative(),
  }),
  errors: z.array(scannerErrorOutputSchema),
  durationMs: z.number(),
  ruleFreshness: RuleFreshnessSchema,
  diffContext: diffContextOutputSchema.optional(),
};

const scanOutputSchema = {
  targetType: z.literal('path'),
  targetPath: z.string(),
  ...scanSummaryOutputSchema,
};

const scanUrlOutputSchema = {
  targetType: z.literal('url'),
  targetUrl: z.string(),
  ...scanSummaryOutputSchema,
};

const auditOutputSchema = {
  format: z.enum(['json', 'html', 'markdown', 'pdf', 'agent']),
  content: z.string().describe('The rendered report content'),
  metadata: z.object({
    targetName: z.string(),
    targetPath: z.string(),
    scanDurationMs: z.number(),
    scannerVersions: z.record(z.string()),
    ruleFreshness: z.object({
      version: z.string(),
      stale: z.boolean(),
    }).optional(),
    packValidation: PackValidationSchema.optional(),
    packCoverage: JurisdictionCoverageSchema.optional(),
    deployDecision: DeployDecisionSchema.optional(),
    diffContext: diffContextOutputSchema.optional(),
  }).optional(),
};

const mapOutputSchema = {
  jurisdiction: Jurisdiction,
  regulationMappings: z.record(z.object({
    status: ControlStatus,
    score: z.number(),
    findingCount: findingCountOutputSchema,
  })),
  appMappings: z.record(z.object({
    status: ControlStatus,
    score: z.number(),
    findingCount: findingCountOutputSchema,
  })),
};

const opinionOutputSchema = ComplianceOpinionSchema.shape;

const checkOutputSchema = {
  jurisdiction: Jurisdiction,
  principle: RegulationPrinciple,
  verdict: z.enum(['COMPLIANT', 'PARTIALLY_COMPLIANT', 'NON_COMPLIANT']),
  score: z.number(),
  confidence: z.enum(['HIGH', 'MODERATE', 'LOW']),
  findings: z.array(z.object({
    id: z.string(),
    severity: Severity,
    title: z.string(),
    fix: z.string().optional(),
  })),
  remediations: z.array(z.string()),
};

const complianceCheckOutputSchema = {
  readinessScore: z.number(),
  readinessLabel: z.enum(['Ready', 'Nearly Ready', 'Needs Work', 'Not Ready', 'Unknown']),
  verdict: z.enum(['compliant', 'partially_compliant', 'non_compliant', 'unknown']),
  summary: z.string(),
  actions: z.array(z.object({
    priority: z.enum(['urgent', 'high', 'medium', 'low']),
    title: z.string(),
    description: z.string(),
    principle: APPPrincipleSchema,
  })),
  gaps: z.array(z.object({
    principle: APPPrincipleSchema.optional(),
    shortName: z.string(),
    description: z.string(),
    status: z.enum(['missing', 'partial', 'unknown']),
  })),
  reformWarnings: z.array(z.object({
    provision: z.string(),
    shortName: z.string(),
    impact: z.enum(['critical', 'high', 'medium']),
    deadline: z.string(),
    actionNeeded: z.string(),
  })).optional(),
  metadata: z.object({
    target: z.object({
      name: z.string(),
      path: z.string().optional(),
      url: z.string().optional(),
      version: z.string().optional(),
    }),
    scanDurationMs: z.number(),
    scannerVersions: z.record(z.string()),
  }),
};

const reformOutputSchema = reformImpactAssessmentSchema.shape;

function makeToolError(message: string): ToolErrorResponse {
  return {
    content: [{ type: 'text', text: message }],
    isError: true,
  };
}

function isToolError(value: unknown): value is ToolErrorResponse {
  return typeof value === 'object' && value !== null && (value as ToolResponse).isError === true;
}

function makeJsonToolResponse(payload: Record<string, unknown>): ToolResponse {
  const text = JSON.stringify(payload, null, 2);
  return {
    content: [{ type: 'text', text }],
    structuredContent: normalizeStructuredContent(payload),
  };
}

function normalizeStructuredContent(payload: Record<string, unknown>): Record<string, unknown> {
  return JSON.parse(JSON.stringify(payload)) as Record<string, unknown>;
}

function getAllowedRoots(): string[] {
  if (!process.env.ATTESTLENS_ALLOWED_ROOTS) {
    return [process.cwd()];
  }
  return process.env.ATTESTLENS_ALLOWED_ROOTS
    .split(path.delimiter)
    .map((root) => root.trim())
    .filter(Boolean);
}

async function getAllowedRootResources(): Promise<AllowedRootResource[]> {
  const resources: AllowedRootResource[] = [];
  const seen = new Set<string>();

  for (const root of getAllowedRoots()) {
    try {
      const realRoot = await fs.realpath(path.resolve(root));
      const stat = await fs.stat(realRoot);
      if (!stat.isDirectory() || seen.has(realRoot)) {
        continue;
      }

      seen.add(realRoot);
      resources.push({
        name: path.basename(realRoot) || realRoot,
        description: 'Allowed scan root directory',
        path: realRoot,
      });
    } catch {
      // Missing or unreadable roots are inactive.
    }
  }

  return resources;
}

function isPathWithinRoot(target: string, root: string): boolean {
  if (target === root) {
    return true;
  }
  const relative = path.relative(root, target);
  return relative !== '' && !relative.startsWith('..') && !path.isAbsolute(relative);
}

export async function validatePath(targetPath: unknown): Promise<string | ToolErrorResponse> {
  if (!targetPath || typeof targetPath !== 'string') {
    return makeToolError('path is required');
  }
  if (/[;|`$\\]/.test(targetPath)) {
    return makeToolError('path contains invalid characters');
  }

  const resolved = path.resolve(targetPath);
  const resolvedRoots: string[] = [];
  const canonicalRoots: string[] = [];
  for (const root of getAllowedRoots()) {
    const resolvedRoot = path.resolve(root);
    try {
      canonicalRoots.push(await fs.realpath(resolvedRoot));
      resolvedRoots.push(resolvedRoot);
    } catch {
      // Missing or unreadable roots are inactive.
    }
  }

  if (canonicalRoots.length === 0) {
    return makeToolError('no valid allowed roots configured');
  }

  const isCandidate = resolvedRoots.some((root) => isPathWithinRoot(resolved, root))
    || canonicalRoots.some((root) => isPathWithinRoot(resolved, root));
  if (!isCandidate) {
    return makeToolError('path is outside allowed workspace roots');
  }

  let realTarget: string;
  try {
    realTarget = await fs.realpath(resolved);
  } catch {
    return makeToolError('path is outside allowed workspace roots');
  }

  let stat;
  try {
    stat = await fs.stat(realTarget);
  } catch {
    return makeToolError('path is outside allowed workspace roots');
  }

  if (!stat.isDirectory()) {
    return makeToolError('path is not a directory');
  }

  const isAllowed = canonicalRoots.some((root) => isPathWithinRoot(realTarget, root));
  if (!isAllowed) {
    return makeToolError('path is outside allowed workspace roots');
  }

  return realTarget;
}

async function revalidatePathBeforeScan(validatedPath: string): Promise<string | ToolErrorResponse> {
  const revalidatedPath = await validatePath(validatedPath);
  if (isToolError(revalidatedPath)) {
    return makeToolError('path changed after validation');
  }

  if (revalidatedPath !== validatedPath) {
    return makeToolError('path changed after validation');
  }

  // This narrows the MCP validation-to-scan swap window. Full TOCTOU protection
  // needs descriptor-relative traversal/O_PATH on Linux or OS sandboxing.
  return revalidatedPath;
}

export function validateUrl(targetUrl: unknown): string | ToolErrorResponse {
  if (!targetUrl || typeof targetUrl !== 'string') {
    return makeToolError('url is required');
  }

  let parsed: URL;
  try {
    parsed = new URL(targetUrl);
  } catch {
    return makeToolError(`invalid URL: ${sanitizeTargetUrlForOutput(targetUrl)}`);
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return makeToolError(`unsupported URL protocol: ${parsed.protocol}`);
  }

  return parsed.toString();
}

function createOrchestrator(
  targetKind: 'path' | 'url',
  options: {
    externalEnrichment?: boolean;
    includeTyposquat?: boolean;
    behavioral?: boolean;
    iac?: boolean;
    includeGitleaks?: boolean;
    scannerTimeoutMs?: number;
    reform?: boolean;
    jurisdiction?: JurisdictionType;
  } = {},
): ScannerOrchestrator {
  const externalEnrichment = targetKind === 'path' && options.externalEnrichment === true;
  const orchestratorOptions: ScannerOrchestratorOptions = {
    adapterTimeoutMs: options.scannerTimeoutMs,
    jurisdictions: [options.jurisdiction ?? 'au-privacy-act'],
    supplyChain: {
      typosquat: { enabled: targetKind === 'path' && options.includeTyposquat === true },
      osv: { enabled: externalEnrichment },
      registry: { enabled: externalEnrichment },
    },
    behavioral: {
      enabled: targetKind === 'path' && options.behavioral !== false,
    },
    iac: {
      enabled: targetKind === 'path' && options.iac !== false,
    },
    gitleaks: {
      enabled: targetKind === 'path' && options.includeGitleaks === true,
      path: getServerConfiguredGitleaksPath(),
    },
    reform: {
      enabled: targetKind === 'path' && options.reform === true,
    },
  };
  const orchestrator = new ScannerOrchestrator(orchestratorOptions);
  if (targetKind === 'url') {
    orchestrator.disable('guardvibe');
    orchestrator.disable('mcp-scan');
    orchestrator.disable('supply-chain');
  }
  return orchestrator;
}

function getServerConfiguredGitleaksPath(): string {
  const configuredPath = process.env.ATTESTLENS_GITLEAKS_PATH?.trim();
  if (!configuredPath) {
    return 'gitleaks';
  }
  return configuredPath;
}

function runScan(
  orchestrator: ScannerOrchestrator,
  target: string,
  signal?: AbortSignal,
  options: Omit<NonNullable<Parameters<ScannerOrchestrator['scan']>[2]>, 'signal'> = {},
): ReturnType<ScannerOrchestrator['scan']> {
  return orchestrator.scan(target, undefined, { ...options, signal });
}

function parseScannerTimeoutMs(value: unknown): number | undefined | ToolErrorResponse {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (typeof value !== 'number' || !Number.isInteger(value) || value <= 0) {
    return makeToolError('scannerTimeoutMs must be a positive integer number of milliseconds');
  }
  if (value > MAX_SCANNER_TIMEOUT_MS) {
    return makeToolError(`scannerTimeoutMs must be ${MAX_SCANNER_TIMEOUT_MS} milliseconds or less`);
  }
  return value;
}

function validatePrinciple(value: unknown): APPPrinciple | ToolErrorResponse {
  if (typeof value !== 'string' || !Object.prototype.hasOwnProperty.call(APPInfo, value)) {
    return makeToolError(`invalid APP principle: ${String(value)}. Valid principles: ${Object.keys(APPInfo).join(', ')}`);
  }
  return value as APPPrinciple;
}

function parseJurisdiction(value: unknown): JurisdictionType | ToolErrorResponse {
  const result = Jurisdiction.safeParse(value ?? 'au-privacy-act');
  if (!result.success) {
    return makeToolError(`unsupported jurisdiction: ${String(value)}. Valid jurisdictions: ${Jurisdiction.options.join(', ')}`);
  }
  return result.data;
}

function validateJurisdictionAvailability(jurisdiction: JurisdictionType): true | ToolErrorResponse {
  Jurisdiction.parse(jurisdiction);
  return true;
}

function getJurisdictionAssessmentLabel(jurisdiction: JurisdictionType): string {
  if (jurisdiction === 'us-ccpa') {
    return 'CCPA';
  }
  if (jurisdiction === 'eu-gdpr') {
    return 'GDPR';
  }
  return 'AU Privacy Act';
}

function validateRegulationPrinciple(
  jurisdiction: JurisdictionType,
  value: unknown,
): RegulationPrinciple | ToolErrorResponse {
  const availability = validateJurisdictionAvailability(jurisdiction);
  if (isToolError(availability)) {
    return availability;
  }

  const registry = getRegistry(jurisdiction);
  if (typeof value !== 'string' || !Object.prototype.hasOwnProperty.call(registry.principles, value)) {
    return makeToolError(
      `Unknown principle ${String(value)} for jurisdiction ${jurisdiction}. Valid principles: ${registry.order.join(', ')}`,
    );
  }
  return value as RegulationPrinciple;
}

function serializeFindings(findings: AttestLensFinding[]) {
  return findings.map((finding: AttestLensFinding) => ({
    id: finding.id,
    source: finding.source,
    sourceRule: finding.sourceRule,
    severity: finding.severity,
    title: finding.title,
    description: finding.description,
    file: finding.file,
    line: finding.line,
    url: finding.url,
    fix: finding.fix,
    fixPrompt: finding.fixPrompt,
    corroboratedBy: finding.corroboratedBy,
    introducedInDiff: finding.introducedInDiff,
    regulationMappings: (finding.regulationMappings ?? []).map((mapping) => ({
      jurisdiction: mapping.jurisdiction,
      principle: mapping.principle,
      obligation: mapping.obligation,
      status: mapping.status,
      confidence: mapping.confidence,
      citation: mapping.citation,
    })),
    appMappings: finding.appMappings.map((mapping) => ({
      principle: mapping.principle,
      obligation: mapping.obligation,
      status: mapping.status,
      confidence: mapping.confidence,
    })),
  }));
}

export function sanitizeMcpErrors(errors: ScannerError[]): SanitizedScannerError[] {
  return errors.map((error) => ({
    source: error.source,
    code: error.code,
    recoverable: error.recoverable,
    message: 'Scan error occurred',
  }));
}

function collectUrlScanErrors(
  result: Awaited<ReturnType<ScannerOrchestrator['scan']>>,
  urlResult?: ScannerResult,
): ScannerError[] {
  const resultErrors = urlResult?.errors ?? [];
  const orchestratorErrors = result.errors.filter((error) => error.source === 'url-scan');
  return [...resultErrors, ...orchestratorErrors];
}

function getUrlScanFailureError(
  result: Awaited<ReturnType<ScannerOrchestrator['scan']>>,
): ToolErrorResponse | null {
  const urlResult = result.results.find((scannerResult) => scannerResult.source === 'url-scan');
  const urlErrors = collectUrlScanErrors(result, urlResult);

  if (!urlResult && urlErrors.length > 0) {
    return formatUrlScanFailure(urlErrors[0]);
  }

  if (!urlResult) {
    return makeToolError('URL scan failed before any findings could be collected.');
  }

  const fatalError = urlErrors.find((error) => !error.recoverable);
  if (fatalError) {
    return formatUrlScanFailure(fatalError);
  }

  if (urlErrors.length > 0 && urlResult.findings.length === 0) {
    return formatUrlScanFailure(urlErrors[0]);
  }

  return null;
}

function formatUrlScanFailure(error: ScannerError): ToolErrorResponse {
  switch (error.code) {
    case 'INVALID_URL':
      return makeToolError('URL target is not allowed for scanning.');
    case 'FETCH_FAILED':
      return makeToolError('URL scan failed before any findings could be collected.');
    default:
      return makeToolError('URL scan failed before any findings could be collected.');
  }
}

function buildScanSummary(
  result: Awaited<ReturnType<ScannerOrchestrator['scan']>>,
  strictMode = false,
  jurisdiction: JurisdictionType = 'au-privacy-act',
) {
  const { controls, unmapped } = mapAllFindings(result.findings, {
    strictMode,
    jurisdictions: [jurisdiction],
  });
  return {
    findings: serializeFindings(result.findings),
    controls: controls.map((control) => ({
      jurisdiction: control.jurisdiction,
      principle: control.principle,
      shortName: control.shortName,
      status: control.status,
      score: control.score,
    })),
    summary: {
      total: result.findings.length,
      critical: result.findings.filter((finding) => finding.severity === 'critical').length,
      high: result.findings.filter((finding) => finding.severity === 'high').length,
      medium: result.findings.filter((finding) => finding.severity === 'medium').length,
      low: result.findings.filter((finding) => finding.severity === 'low').length,
      info: result.findings.filter((finding) => finding.severity === 'info').length,
      affectedPrinciples: controls.filter((control) => control.status === 'fail').map((control) => control.principle),
      unmappedCount: unmapped.length,
    },
    errors: sanitizeMcpErrors(result.errors),
    durationMs: result.totalDurationMs,
    ruleFreshness: RuleFreshnessSchema.parse(result.ruleFreshness),
    diffContext: result.diffContext,
  };
}

async function resolveMcpDiffContext(args: Record<string, unknown> | undefined, cwd: string): Promise<DiffContext | ToolErrorResponse | undefined> {
  const diffBase = typeof args?.diffBase === 'string' && args.diffBase.trim().length > 0
    ? args.diffBase
    : undefined;
  const diffHead = typeof args?.diffHead === 'string' && args.diffHead.trim().length > 0
    ? args.diffHead
    : undefined;
  const changedFiles = Array.isArray(args?.changedFiles)
    ? args.changedFiles.filter((file): file is string => typeof file === 'string')
    : undefined;

  if (!diffBase && !diffHead && !changedFiles?.length && args?.changedFilesOnly !== true) {
    return undefined;
  }
  if ((diffBase && !diffHead) || (!diffBase && diffHead)) {
    return makeToolError('diffBase and diffHead must be supplied together.');
  }
  if (!changedFiles?.length && (!diffBase || !diffHead)) {
    return makeToolError('diffBase and diffHead are required when changedFiles are not supplied.');
  }

  try {
    return await buildDiffContext({
      cwd,
      baseRef: diffBase,
      headRef: diffHead,
      changedFiles,
    });
  } catch (error) {
    return makeToolError(error instanceof Error ? error.message : String(error));
  }
}

function parseReportFormat(rawFormat: unknown): ReportFormat | ToolErrorResponse {
  const format = typeof rawFormat === 'string' ? rawFormat : 'json';
  if (format === 'json' || format === 'html' || format === 'markdown' || format === 'pdf' || format === 'agent') {
    return format;
  }
  return makeToolError(`unsupported report format: ${format}`);
}

async function renderAuditContent(
  report: ReturnType<typeof buildComplianceReport>,
  reportOptions: ReportOptions,
  format: ReportFormat,
): Promise<string> {
  switch (format) {
    case 'html':
      return generateHTMLReport(report, reportOptions);
    case 'markdown':
      return generateMarkdownReport(report);
    case 'agent':
      return generateAgentReport(report);
    case 'pdf': {
      const pdf = await generatePDFReport(report, reportOptions);
      return JSON.stringify(
        {
          format: 'pdf',
          encoding: 'base64',
          filename: `attestlens-report-${report.target.name.toLowerCase().replace(/[^a-z0-9]+/g, '-')}.pdf`,
          mimeType: 'application/pdf',
          content: pdf.toString('base64'),
        },
        null,
        2,
      );
    }
    case 'json':
    default:
      return generateJSONReport(report);
  }
}

export async function handleToolCall(name: string, args: Record<string, unknown> | undefined, extra: ToolCallExtra = {}): Promise<ToolResponse> {
  switch (name) {
    case 'attestlens_scan': {
      const targetPath = await validatePath(args?.path);
      if (isToolError(targetPath)) {
        return targetPath;
      }
      const scanPath = await revalidatePathBeforeScan(targetPath);
      if (isToolError(scanPath)) {
        return scanPath;
      }
      const strict = args?.strict === true;
      const externalEnrichment = args?.externalEnrichment === true;
      const includeTyposquat = args?.includeTyposquat === true;
      const behavioral = args?.behavioral !== false;
      const iac = args?.iac !== false;
      const includeGitleaks = args?.includeGitleaks === true;
      const scannerTimeoutMs = parseScannerTimeoutMs(args?.scannerTimeoutMs);
      if (isToolError(scannerTimeoutMs)) {
        return scannerTimeoutMs;
      }
      const jurisdiction = parseJurisdiction(args?.jurisdiction);
      if (isToolError(jurisdiction)) {
        return jurisdiction;
      }
      const jurisdictionAvailability = validateJurisdictionAvailability(jurisdiction);
      if (isToolError(jurisdictionAvailability)) {
        return jurisdictionAvailability;
      }
      const diffContext = await resolveMcpDiffContext(args, scanPath);
      if (isToolError(diffContext)) {
        return diffContext;
      }

      const orchestrator = createOrchestrator('path', { externalEnrichment, includeTyposquat, behavioral, iac, includeGitleaks, scannerTimeoutMs, jurisdiction });
      const result = await runScan(orchestrator, scanPath, extra.signal, {
        diffContext,
        changedFilesOnly: args?.changedFilesOnly === true,
      });

      return makeJsonToolResponse({
        targetType: 'path',
        targetPath: sanitizeTargetPathForOutput(scanPath),
        ...buildScanSummary(result, strict, jurisdiction),
      });
    }

    case 'attestlens_scan_url': {
      const targetUrl = validateUrl(args?.url);
      if (isToolError(targetUrl)) {
        return targetUrl;
      }
      const strict = args?.strict === true;
      const scannerTimeoutMs = parseScannerTimeoutMs(args?.scannerTimeoutMs);
      if (isToolError(scannerTimeoutMs)) {
        return scannerTimeoutMs;
      }
      const jurisdiction = parseJurisdiction(args?.jurisdiction);
      if (isToolError(jurisdiction)) {
        return jurisdiction;
      }
      const jurisdictionAvailability = validateJurisdictionAvailability(jurisdiction);
      if (isToolError(jurisdictionAvailability)) {
        return jurisdictionAvailability;
      }

      const orchestrator = createOrchestrator('url', { scannerTimeoutMs, jurisdiction });
      const result = await runScan(orchestrator, targetUrl, extra.signal);
      const urlScanFailure = getUrlScanFailureError(result);
      if (urlScanFailure) {
        return urlScanFailure;
      }

      return makeJsonToolResponse({
        targetType: 'url',
        targetUrl: sanitizeTargetUrlForOutput(targetUrl),
        ...buildScanSummary(result, strict, jurisdiction),
      });
    }

    case 'attestlens_audit': {
      const targetPath = await validatePath(args?.path);
      if (isToolError(targetPath)) {
        return targetPath;
      }
      const scanPath = await revalidatePathBeforeScan(targetPath);
      if (isToolError(scanPath)) {
        return scanPath;
      }
      const projectName = (args?.name as string) || path.basename(scanPath) || 'project';
      const format = parseReportFormat(args?.format);
      if (isToolError(format)) {
        return format;
      }
      const strict = args?.strict === true;
      const externalEnrichment = args?.externalEnrichment === true;
      const includeTyposquat = args?.includeTyposquat === true;
      const behavioral = args?.behavioral !== false;
      const iac = args?.iac !== false;
      const includeGitleaks = args?.includeGitleaks === true;
      const scannerTimeoutMs = parseScannerTimeoutMs(args?.scannerTimeoutMs);
      if (isToolError(scannerTimeoutMs)) {
        return scannerTimeoutMs;
      }
      const jurisdiction = parseJurisdiction(args?.jurisdiction);
      if (isToolError(jurisdiction)) {
        return jurisdiction;
      }
      const jurisdictionAvailability = validateJurisdictionAvailability(jurisdiction);
      if (isToolError(jurisdictionAvailability)) {
        return jurisdictionAvailability;
      }
      const diffContext = await resolveMcpDiffContext(args, scanPath);
      if (isToolError(diffContext)) {
        return diffContext;
      }

      const orchestrator = createOrchestrator('path', { externalEnrichment, includeTyposquat, behavioral, iac, includeGitleaks, scannerTimeoutMs, jurisdiction });
      const startTime = Date.now();
      const scanResult = await runScan(orchestrator, scanPath, extra.signal, {
        diffContext,
        changedFilesOnly: args?.changedFilesOnly === true,
      });
      const duration = Date.now() - startTime;

      const reportOptions: ReportOptions = {
        targetName: projectName,
        targetPath: scanPath,
        formats: [format],
        outputDir: '/tmp/attestlens-mcp',
        strictMode: strict,
        includeOpinion: args?.opinion === true,
        includeDeployDecision: format === 'agent',
        ruleFreshness: scanResult.ruleFreshness,
        jurisdiction,
        jurisdictionPack: scanResult.jurisdictionManifests?.[jurisdiction],
        packValidationTrusted: scanResult.ruleFreshness.source === 'embedded',
        diffContext: scanResult.diffContext,
      };
      const report = buildComplianceReport(scanResult.findings, reportOptions, duration);
      report.metadata.scannerVersions = Object.fromEntries(
        scanResult.results.map((scannerResult) => [scannerResult.source, scannerResult.version]),
      );

      const renderedContent = await renderAuditContent(report, reportOptions, format);
      const auditEnvelope = {
        format,
        content: renderedContent,
        metadata: {
          targetName: report.target.name,
          targetPath: report.target.path ?? sanitizeTargetPathForOutput(scanPath),
          scanDurationMs: report.metadata.scanDurationMs,
          scannerVersions: report.metadata.scannerVersions,
          ruleFreshness: report.metadata.ruleFreshness
            ? {
              version: report.metadata.ruleFreshness.version,
              stale: report.metadata.ruleFreshness.stale,
            }
            : undefined,
          packValidation: report.metadata.packValidation,
          packCoverage: report.metadata.packCoverage,
          deployDecision: report.deployDecision,
          diffContext: report.metadata.diffContext,
        },
      };
      return {
        content: [{
          type: 'text',
          text: renderedContent,
        }],
        structuredContent: normalizeStructuredContent(auditEnvelope),
      };
    }

    case 'attestlens_map': {
      const jurisdiction = parseJurisdiction(args?.jurisdiction);
      if (isToolError(jurisdiction)) {
        return jurisdiction;
      }
      const jurisdictionAvailability = validateJurisdictionAvailability(jurisdiction);
      if (isToolError(jurisdictionAvailability)) {
        return jurisdictionAvailability;
      }

      const rawFindings = args?.findings as Array<Record<string, unknown>> | undefined;
      if (!rawFindings || !Array.isArray(rawFindings)) {
        return makeToolError('findings array is required');
      }

      const findings: AttestLensFinding[] = rawFindings.map((finding, index) => ({
        id: (finding.id as string) || `FIND-${index + 1}`,
        source: (finding.source as AttestLensFinding['source']) || 'manual',
        sourceRule: finding.sourceRule as string,
        severity: (finding.severity as AttestLensFinding['severity']) || 'medium',
        category: (finding.category as string) || 'Security',
        title: finding.title as string,
        description: (finding.description as string) || '',
        file: finding.file as string | undefined,
        line: finding.line as number | undefined,
        regulationMappings: [],
        appMappings: [],
        evidence: {
          timestamp: new Date().toISOString(),
          scannerVersion: ATTESTLENS_VERSION,
          rawOutput: finding,
        },
      }));

      const { controls: regulationControls } = mapAllFindings(findings, {
        jurisdictions: [jurisdiction],
      });
      const appControls = jurisdiction === 'au-privacy-act'
        ? regulationControls.filter((control) => Object.prototype.hasOwnProperty.call(APPInfo, control.principle))
        : [];

      return makeJsonToolResponse({
        jurisdiction,
        regulationMappings: Object.fromEntries(
          regulationControls.map((control) => [
            `${control.jurisdiction}:${control.principle}`,
            {
              status: control.status,
              score: control.score,
              findingCount: control.findingCount,
            },
          ]),
        ),
        appMappings: Object.fromEntries(
          appControls.map((control) => [
            control.principle,
            {
              status: control.status,
              score: control.score,
              findingCount: control.findingCount,
            },
          ]),
        ),
      });
    }

    case 'attestlens_opinion': {
      const targetPath = await validatePath(args?.path);
      if (isToolError(targetPath)) {
        return targetPath;
      }
      const scanPath = await revalidatePathBeforeScan(targetPath);
      if (isToolError(scanPath)) {
        return scanPath;
      }
      const strict = args?.strict === true;
      const jurisdiction = parseJurisdiction(args?.jurisdiction);
      if (isToolError(jurisdiction)) {
        return jurisdiction;
      }
      const jurisdictionAvailability = validateJurisdictionAvailability(jurisdiction);
      if (isToolError(jurisdictionAvailability)) {
        return jurisdictionAvailability;
      }

      const orchestrator = createOrchestrator('path', { jurisdiction });
      const startTime = Date.now();
      const scanResult = await runScan(orchestrator, scanPath, extra.signal);
      const duration = Date.now() - startTime;

      const reportOptions: ReportOptions = {
        targetName: path.basename(scanPath) || 'project',
        targetPath: scanPath,
        formats: ['json'],
        outputDir: '/tmp/attestlens-mcp',
        strictMode: strict,
        includeOpinion: true,
        ruleFreshness: scanResult.ruleFreshness,
        jurisdiction,
        jurisdictionPack: scanResult.jurisdictionManifests?.[jurisdiction],
        packValidationTrusted: scanResult.ruleFreshness.source === 'embedded',
      };
      const report = buildComplianceReport(scanResult.findings, reportOptions, duration);
      report.metadata.scannerVersions = Object.fromEntries(
        scanResult.results.map((scannerResult) => [scannerResult.source, scannerResult.version]),
      );

      // Return just the opinion, not the full report
      const opinion = report.complianceOpinion;
      if (!opinion) {
        return makeToolError('Opinion generation failed');
      }

      return makeJsonToolResponse(opinion);
    }

    case 'attestlens_check': {
      const targetPath = await validatePath(args?.path);
      if (isToolError(targetPath)) {
        return targetPath;
      }
      const scanPath = await revalidatePathBeforeScan(targetPath);
      if (isToolError(scanPath)) {
        return scanPath;
      }
      const jurisdiction = parseJurisdiction(args?.jurisdiction);
      if (isToolError(jurisdiction)) {
        return jurisdiction;
      }
      const principle = validateRegulationPrinciple(jurisdiction, args?.principle);
      if (isToolError(principle)) {
        return principle;
      }
      const strict = args?.strict === true;

      const orchestrator = createOrchestrator('path', { jurisdiction });
      const startTime = Date.now();
      const scanResult = await runScan(orchestrator, scanPath, extra.signal);
      const duration = Date.now() - startTime;

      const reportOptions: ReportOptions = {
        targetName: path.basename(scanPath) || 'project',
        targetPath: scanPath,
        formats: ['json'],
        outputDir: '/tmp/attestlens-mcp',
        strictMode: strict,
        includeOpinion: true,
        ruleFreshness: scanResult.ruleFreshness,
        jurisdiction,
        jurisdictionPack: scanResult.jurisdictionManifests?.[jurisdiction],
        packValidationTrusted: scanResult.ruleFreshness.source === 'embedded',
      };
      const report = buildComplianceReport(scanResult.findings, reportOptions, duration);
      report.metadata.scannerVersions = Object.fromEntries(
        scanResult.results.map((scannerResult) => [scannerResult.source, scannerResult.version]),
      );

      const controls = report.regulationControls ?? report.appControls.map((appControl) => ({
        jurisdiction: 'au-privacy-act' as const,
        ...appControl,
      }));
      const control = controls.find((candidate) => candidate.jurisdiction === jurisdiction && candidate.principle === principle);
      if (!control) {
        return makeToolError(`principle not found in report: ${principle}`);
      }

      const opinion = report.complianceOpinion?.principles.find((principleOpinion) => (
        principleOpinion.principle === principle
      ));
      if (!opinion) {
        return makeToolError(`Opinion generation failed for ${principle}`);
      }

      const findingIds = new Set(control.findings);
      const findings = report.findings
        .filter((finding) => findingIds.has(finding.id))
        .map((finding) => ({
          id: finding.id,
          severity: finding.severity,
          title: finding.title,
          fix: finding.fix,
        }));

      return makeJsonToolResponse({
        jurisdiction,
        principle,
        verdict: opinion.verdict,
        score: opinion.score,
        confidence: opinion.confidence,
        findings,
        remediations: findings
          .map((finding) => finding.fix)
          .filter((fix): fix is string => typeof fix === 'string' && fix.length > 0),
      });
    }

    case 'attestlens_compliance_check': {
      const targetPath = await validatePath(args?.path);
      if (isToolError(targetPath)) {
        return targetPath;
      }
      const scanPath = await revalidatePathBeforeScan(targetPath);
      if (isToolError(scanPath)) {
        return scanPath;
      }
      const strict = args?.strict === true;
      const reform = args?.reform === true;
      const jurisdiction = parseJurisdiction(args?.jurisdiction);
      if (isToolError(jurisdiction)) {
        return jurisdiction;
      }
      const jurisdictionAvailability = validateJurisdictionAvailability(jurisdiction);
      if (isToolError(jurisdictionAvailability)) {
        return jurisdictionAvailability;
      }
      if (jurisdiction !== 'au-privacy-act') {
        return makeToolError(`SMB compliance check is currently AU-only; use \`audit --jurisdiction ${jurisdiction}\` for ${getJurisdictionAssessmentLabel(jurisdiction)} assessments.`);
      }

      const orchestrator = createOrchestrator('path', {
        externalEnrichment: false,
        includeTyposquat: false,
        behavioral: true,
        iac: true,
        includeGitleaks: false,
        reform,
        jurisdiction,
      });
      const scanResult = await runScan(orchestrator, scanPath, extra.signal);
      const duration = scanResult.totalDurationMs;

      const reportOptions: ReportOptions = {
        targetName: path.basename(scanPath) || 'project',
        targetPath: sanitizeTargetPathForOutput(scanPath),
        formats: ['smb'],
        outputDir: './attestlens-reports',
        strictMode: strict,
        includeReform: reform,
        includeSMB: true,
        ruleFreshness: scanResult.ruleFreshness,
        jurisdiction,
        jurisdictionPack: scanResult.jurisdictionManifests?.[jurisdiction],
        packValidationTrusted: scanResult.ruleFreshness.source === 'embedded',
      };

      const report = buildComplianceReport(scanResult.findings, reportOptions, duration) as ComplianceReportWithSMB;
      report.metadata.scannerVersions = Object.fromEntries(
        scanResult.results.map((scannerResult) => [scannerResult.source, scannerResult.version]),
      );

      const smbResult = report.smbCompliance ?? buildSMBComplianceResult(report);
      if (!smbResult) {
        return makeToolError('Failed to generate SMB compliance result');
      }

      const gapControls = report.appControls.filter((control) => control.status === 'unknown');
      const reformProvisions = report.reformImpactAssessment?.provisions.filter((provision) => (
        provision.findingCount > 0
      )) ?? [];

      return makeJsonToolResponse({
        readinessScore: smbResult.readinessScore,
        readinessLabel: smbResult.readinessLabel,
        verdict: smbResult.verdict,
        summary: smbResult.summary,
        actions: smbResult.actions.map((action) => ({
          priority: action.priority,
          title: action.title,
          description: action.description,
          principle: action.principle,
        })),
        gaps: smbResult.gaps.map((gap, index) => {
          const control = gapControls[index];
          return {
            principle: control?.principle,
            shortName: control?.shortName ?? gap.area,
            description: gap.description,
            status: gap.status,
          };
        }),
        reformWarnings: smbResult.reformWarnings?.map((warning, index) => {
          const provision = reformProvisions[index];
          return {
            provision: warning.provision,
            shortName: provision?.shortName ?? warning.provision,
            impact: warning.impact,
            deadline: warning.deadline,
            actionNeeded: warning.description,
          };
        }),
        metadata: {
          target: report.target,
          scanDurationMs: duration,
          scannerVersions: report.metadata.scannerVersions,
        },
      });
    }

    case 'attestlens_reform': {
      const targetPath = await validatePath(args?.path);
      if (isToolError(targetPath)) {
        return targetPath;
      }
      const scanPath = await revalidatePathBeforeScan(targetPath);
      if (isToolError(scanPath)) {
        return scanPath;
      }
      const strict = args?.strict === true;

      const orchestrator = createOrchestrator('path', { reform: true });
      const startTime = Date.now();
      const scanResult = await runScan(orchestrator, scanPath, extra.signal);
      const duration = Date.now() - startTime;

      const reportOptions: ReportOptions = {
        targetName: path.basename(scanPath) || 'project',
        targetPath: scanPath,
        formats: ['json'],
        outputDir: '/tmp/attestlens-mcp',
        strictMode: strict,
        includeReform: true,
        ruleFreshness: scanResult.ruleFreshness,
        jurisdiction: 'au-privacy-act',
        jurisdictionPack: scanResult.jurisdictionManifests?.['au-privacy-act'],
        packValidationTrusted: scanResult.ruleFreshness.source === 'embedded',
      };
      const report = buildComplianceReport(scanResult.findings, reportOptions, duration);
      report.metadata.scannerVersions = Object.fromEntries(
        scanResult.results.map((scannerResult) => [scannerResult.source, scannerResult.version]),
      );

      const assessment: ReformImpactAssessment | undefined = report.reformImpactAssessment;
      if (!assessment) {
        return makeToolError('Reform impact assessment generation failed');
      }

      return makeJsonToolResponse(assessment);
    }

    default:
      throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
  }
}

function getToolDefinition(name: (typeof TOOL_DEFINITIONS)[number]['name']) {
  const definition = TOOL_DEFINITIONS.find((tool) => tool.name === name);
  if (!definition) {
    throw new Error(`Unknown tool definition: ${name}`);
  }
  return definition;
}

function registerStructuredTool(
  server: McpServer,
  name: (typeof TOOL_DEFINITIONS)[number]['name'],
  inputSchema: Record<string, z.ZodTypeAny>,
  outputSchema: Record<string, z.ZodTypeAny>,
): void {
  const definition = getToolDefinition(name);
  server.registerTool(name, {
    title: definition.title,
    description: definition.description,
    inputSchema,
    outputSchema,
    annotations: definition.annotations,
  }, async (args, extra) => handleToolCall(name, args as Record<string, unknown>, { signal: extra.signal }));
}

function registerResourceHandlers(server: McpServer): void {
  const resourcesByUri = new Map<string, ListedAllowedRootResource>();

  server.server.setRequestHandler(ResourcesListSchema, async () => {
    const resources = await getAllowedRootResources();
    resourcesByUri.clear();
    const listedResources = resources.map((resource, index) => {
      const listedResource: ListedAllowedRootResource = {
        ...resource,
        uri: `attestlens://root/${index}`,
      };
      resourcesByUri.set(listedResource.uri, listedResource);
      return listedResource;
    });

    return {
      resources: listedResources.map(({ uri, name, description }) => ({
        uri,
        name,
        description,
      })),
    };
  });

  server.server.setRequestHandler(ResourcesReadSchema, async (request) => {
    const requestedUri = typeof request.params.uri === 'string' ? request.params.uri : '';
    const resource = resourcesByUri.get(requestedUri);
    if (!resource) {
      throw new McpError(-32002, 'Resource not found');
    }

    return {
      contents: [
        {
          uri: resource.uri,
          mimeType: 'text/plain',
          text: [
            resource.description,
            `Name: ${resource.name}`,
            'AttestLens can scan files under this root when a tool call targets it.',
            'Directory contents are intentionally not exposed through MCP resources.',
          ].join('\n'),
        },
      ],
    };
  });
}

export function createServer(): McpServer {
  const server = new McpServer(
    { name: 'attestlens', version: ATTESTLENS_VERSION },
    { capabilities: { tools: {}, resources: {} } },
  );

  registerStructuredTool(server, 'attestlens_scan', scanInputSchema, scanOutputSchema);
  registerStructuredTool(server, 'attestlens_scan_url', scanUrlInputSchema, scanUrlOutputSchema);
  registerStructuredTool(server, 'attestlens_audit', auditInputSchema, auditOutputSchema);
  registerStructuredTool(server, 'attestlens_map', mapInputSchema, mapOutputSchema);
  registerStructuredTool(server, 'attestlens_opinion', opinionInputSchema, opinionOutputSchema);
  registerStructuredTool(server, 'attestlens_check', checkInputSchema, checkOutputSchema);
  registerStructuredTool(server, 'attestlens_compliance_check', complianceCheckInputSchema, complianceCheckOutputSchema);
  registerStructuredTool(server, 'attestlens_reform', reformInputSchema, reformOutputSchema);
  registerResourceHandlers(server);

  return server;
}

export const server = createServer();

export async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('AttestLens MCP server running on stdio');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
}
