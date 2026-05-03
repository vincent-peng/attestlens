import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

import { getRegistry } from '../jurisdiction/registry.js';
import type {
  AttestLensFinding,
  DeployDecision,
  Jurisdiction,
  RegulationMapping,
  RegulationPrinciple,
} from '../schema/index.js';

export type SarifLevel = 'error' | 'warning' | 'note';
export type SarifProblemSeverity = 'error' | 'warning' | 'recommendation';
export type SarifPrecision = 'very-high' | 'high' | 'medium' | 'low';

export interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  helpUri: string;
  properties: {
    tags: string[];
    precision: SarifPrecision;
    'problem.severity': SarifProblemSeverity;
  };
}

export interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: SarifLevel;
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region: { startLine: number; startColumn: number };
    };
  }>;
  partialFingerprints: {
    primaryLocationLineHash: string;
  };
}

export interface SarifOutput {
  $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json';
  version: '2.1.0';
  runs: Array<{
    tool: {
      driver: {
        name: 'Clearway';
        version: string;
        informationUri: 'https://clearway.ai';
        rules: SarifRule[];
      };
    };
    results: SarifResult[];
  }>;
}

export interface SarifFormatOptions {
  findings: AttestLensFinding[];
  jurisdiction: Jurisdiction;
  version: string;
  basePath?: string;
  deployDecision?: DeployDecision;
}

const SARIF_SCHEMA = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json' as const;
const SARIF_INFO_URI = 'https://clearway.ai' as const;
const SYNTHETIC_LOCATION_URI = '__target__';

export async function formatSarif(options: SarifFormatOptions): Promise<SarifOutput> {
  const basePathInput = options.basePath;
  const basePath = basePathInput ? await fs.realpath(basePathInput).catch(() => path.resolve(basePathInput)) : undefined;
  const matchingFindings = shouldSuppressSarifResults(options.deployDecision)
    ? []
    : options.findings.filter((finding) => hasJurisdictionMapping(finding, options.jurisdiction));
  const ruleMap = new Map<string, SarifRule>();
  const results: SarifResult[] = [];

  for (const finding of matchingFindings) {
    const mapping = getPrimaryMapping(finding, options.jurisdiction);
    const level = mapFindingToSarifLevel(finding, options.deployDecision);
    const rule = buildSarifRule(finding, mapping, options.jurisdiction, level);
    if (!ruleMap.has(rule.id)) {
      ruleMap.set(rule.id, rule);
    }
  }

  const rules = Array.from(ruleMap.values());
  const ruleIndexById = new Map(rules.map((rule, index) => [rule.id, index]));

  for (const finding of matchingFindings) {
    const mapping = getPrimaryMapping(finding, options.jurisdiction);
    const ruleId = buildJurisdictionQualifiedRuleId(options.jurisdiction, mapping.principle, finding.title);
    const uri = await relativizeFindingPath(finding.file, basePath);
    const startLine = finding.line && finding.line > 0 ? finding.line : 1;

    results.push({
      ruleId,
      ruleIndex: ruleIndexById.get(ruleId) ?? 0,
      level: mapFindingToSarifLevel(finding, options.deployDecision),
      message: {
        text: finding.description || finding.title,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri },
            region: {
              startLine,
              startColumn: 1,
            },
          },
        },
      ],
      partialFingerprints: {
        primaryLocationLineHash: buildPrimaryLocationLineHash(ruleId, uri, startLine),
      },
    });
  }

  return {
    $schema: SARIF_SCHEMA,
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Clearway',
            version: options.version,
            informationUri: SARIF_INFO_URI,
            rules,
          },
        },
        results,
      },
    ],
  };
}

export function mapFindingSeverityToSarifLevel(severity: AttestLensFinding['severity']): SarifLevel {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
    case 'info':
      return 'note';
  }
}

export function mapDeployDecisionToSarifLevel(
  deployDecision: DeployDecision,
  fallbackSeverity: AttestLensFinding['severity'] = 'medium',
): SarifLevel | null {
  switch (deployDecision.verdict) {
    case 'BLOCK':
      return 'error';
    case 'WARN':
      return 'warning';
    case 'NEEDS_REVIEW':
      return fallbackSeverity === 'critical' || fallbackSeverity === 'high' || fallbackSeverity === 'medium'
        ? 'warning'
        : 'note';
    case 'PASS':
    case 'OUT_OF_SCOPE':
      return null;
  }
}

export function sarifLevelToProblemSeverity(level: SarifLevel): SarifProblemSeverity {
  switch (level) {
    case 'error':
      return 'error';
    case 'warning':
      return 'warning';
    case 'note':
      return 'recommendation';
  }
}

export function inferSarifPrecision(
  finding: AttestLensFinding,
  level: SarifLevel = mapFindingSeverityToSarifLevel(finding.severity),
): SarifPrecision {
  if (level === 'note') {
    return 'low';
  }
  if (level === 'warning') {
    return 'medium';
  }
  return finding.corroboratedBy && finding.corroboratedBy.length > 0 ? 'very-high' : 'high';
}

function shouldSuppressSarifResults(deployDecision: DeployDecision | undefined): boolean {
  return deployDecision?.verdict === 'PASS' || deployDecision?.verdict === 'OUT_OF_SCOPE';
}

function mapFindingToSarifLevel(
  finding: AttestLensFinding,
  deployDecision: DeployDecision | undefined,
): SarifLevel {
  const decisionLevel = deployDecision
    ? mapDeployDecisionToSarifLevel(deployDecision, finding.severity)
    : null;
  return decisionLevel ?? mapFindingSeverityToSarifLevel(finding.severity);
}

export function buildPrimaryLocationLineHash(ruleId: string, filePath: string, line: number): string {
  return crypto
    .createHash('sha256')
    .update(`${ruleId}:${filePath}:${line}`)
    .digest('hex')
    .slice(0, 16);
}

export function buildJurisdictionQualifiedRuleId(
  jurisdiction: Jurisdiction,
  principle: RegulationPrinciple,
  title: string,
): string {
  const prefix = buildRulePrefix(jurisdiction, principle);
  const slug = slugifyRuleName(title);
  return `${prefix}.${slug}`;
}

function buildRulePrefix(jurisdiction: Jurisdiction, principle: RegulationPrinciple): string {
  if (jurisdiction === 'au-privacy-act' && principle.startsWith('APP_')) {
    return `AU.APP.${principle.replace('APP_', '').replaceAll('_', '.')}.1`;
  }
  if (jurisdiction === 'au-privacy-act' && principle === 'NDB') {
    return 'AU.NDB.26WE';
  }
  if (jurisdiction === 'us-ccpa' && principle.startsWith('CCPA_')) {
    return `US.CCPA.1798.${principle.replace('CCPA_', '')}`;
  }
  if (jurisdiction === 'eu-gdpr' && principle.startsWith('GDPR_Art')) {
    return `EU.GDPR.ART.${principle.replace('GDPR_Art', '')}`;
  }
  if (jurisdiction === 'sg-pdpa' && principle.startsWith('SGPDPA_')) {
    return `SG.PDPA.${principle.replace('SGPDPA_', '')}`;
  }
  return `${jurisdiction.toUpperCase().replaceAll('-', '.')}.${principle.replaceAll('_', '.')}`;
}

function buildSarifRule(
  finding: AttestLensFinding,
  mapping: RegulationMapping,
  jurisdiction: Jurisdiction,
  level: SarifLevel = mapFindingSeverityToSarifLevel(finding.severity),
): SarifRule {
  const ruleId = buildJurisdictionQualifiedRuleId(jurisdiction, mapping.principle, finding.title);
  const principleInfo = getRegistry(jurisdiction).principles[mapping.principle];
  const obligation = principleInfo?.obligation ?? mapping.obligation;
  const citation = mapping.citation ?? principleInfo?.citation;

  return {
    id: ruleId,
    name: toPascalCase(finding.title),
    shortDescription: { text: finding.title },
    fullDescription: {
      text: citation ? `${obligation} (${citation})` : obligation,
    },
    helpUri: `${SARIF_INFO_URI}/rules/${ruleId}`,
    properties: {
      tags: buildRuleTags(jurisdiction, mapping.principle),
      precision: inferSarifPrecision(finding, level),
      'problem.severity': sarifLevelToProblemSeverity(level),
    },
  };
}

function buildRuleTags(jurisdiction: Jurisdiction, principle: RegulationPrinciple): string[] {
  const jurisdictionTag = jurisdiction === 'au-privacy-act'
    ? 'au-privacy-act'
    : jurisdiction === 'us-ccpa'
      ? 'us-ccpa'
      : jurisdiction === 'eu-gdpr'
        ? 'eu-gdpr'
        : 'sg-pdpa';

  const principleTag = principle
    .toLowerCase()
    .replace(/^app_/, 'app-')
    .replace(/^ccpa_/, 'ccpa-')
    .replace(/^gdpr_art/, 'gdpr-art-')
    .replace(/^sgpdpa_/, 'sgpdpa-')
    .replaceAll('_', '-');

  return ['privacy', jurisdictionTag, principleTag];
}

function hasJurisdictionMapping(finding: AttestLensFinding, jurisdiction: Jurisdiction): boolean {
  return finding.regulationMappings.some((candidate) => candidate.jurisdiction === jurisdiction);
}

function getPrimaryMapping(finding: AttestLensFinding, jurisdiction: Jurisdiction): RegulationMapping {
  const mapping = finding.regulationMappings.find((candidate) => candidate.jurisdiction === jurisdiction);
  if (!mapping) {
    throw new Error(`Finding ${finding.id} is missing a ${jurisdiction} regulation mapping`);
  }
  return mapping;
}

async function relativizeFindingPath(filePath: string | undefined, basePath: string | undefined): Promise<string> {
  if (!filePath) {
    return SYNTHETIC_LOCATION_URI;
  }

  const normalizedInput = filePath.replaceAll('\\', '/');
  if (!path.isAbsolute(filePath)) {
    return normalizedInput.replace(/^\.\/+/, '') || SYNTHETIC_LOCATION_URI;
  }

  const realPath = await fs.realpath(filePath).catch(() => path.resolve(filePath));
  if (!basePath) {
    return path.basename(realPath).replaceAll(path.sep, '/');
  }

  const relative = path.relative(basePath, realPath);
  if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) {
    return path.basename(realPath).replaceAll(path.sep, '/');
  }

  return relative.replaceAll(path.sep, '/');
}

function slugifyRuleName(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/['"]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80) || 'finding';
}

function toPascalCase(value: string): string {
  return value
    .replace(/[^a-zA-Z0-9]+/g, ' ')
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join('');
}
