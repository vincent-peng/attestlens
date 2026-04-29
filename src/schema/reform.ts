import { z } from 'zod';

// ─── Local schema copies (avoids circular import from index.js) ──────────

const _severitySchema = z.enum(['critical', 'high', 'medium', 'low', 'info']);
const _controlStatusSchema = z.enum(['pass', 'fail', 'unknown']);
const _appPrincipleSchema = z.enum([
  'APP_1', 'APP_2', 'APP_3', 'APP_4', 'APP_5',
  'APP_6', 'APP_7', 'APP_8', 'APP_9', 'APP_10',
  'APP_11', 'APP_12', 'APP_13', 'NDB',
]);
const _appMappingSchema = z.object({
  principle: _appPrincipleSchema,
  obligation: z.string(),
  status: _controlStatusSchema,
  confidence: z.number().min(0).max(1),
  rationale: z.string().optional(),
});

// ─── Reform Provisions ────────────────────────────────────────────────────────

export const reformProvisionSchema = z.enum([
  'STATUTORY_TORT',
  'CHILDREN_PRIVACY_CODE',
  'AUTOMATED_DECISION_MAKING',
  'AML_CTF',
]);
export type ReformProvision = z.infer<typeof reformProvisionSchema>;
export const ReformProvision = reformProvisionSchema.enum;

export const ReformProvisionInfo: Record<ReformProvision, {
  shortName: string;
  obligation: string;
  effectiveDate: string;
}> = {
  [ReformProvision.STATUTORY_TORT]: {
    shortName: 'Statutory Tort',
    obligation: 'Privacy Act statutory tort for serious invasions of privacy',
    effectiveDate: '2026-07-01',
  },
  [ReformProvision.CHILDREN_PRIVACY_CODE]: {
    shortName: "Children's Online Privacy Code",
    obligation: "Children's Online Privacy Code requirements for online services likely to be accessed by children",
    effectiveDate: '2026-12-10',
  },
  [ReformProvision.AUTOMATED_DECISION_MAKING]: {
    shortName: 'Automated Decision-Making Transparency',
    obligation: 'Transparency requirements for substantially automated decisions that significantly affect individuals',
    effectiveDate: '2026-12-10',
  },
  [ReformProvision.AML_CTF]: {
    shortName: 'AML/CTF Reforms',
    obligation: 'Anti-Money Laundering and Counter-Terrorism Financing reform obligations',
    effectiveDate: '2026-07-01',
  },
};

// ─── Reform Findings ──────────────────────────────────────────────────────────

export const reformFindingSchema = z.object({
  id: z.string(),
  source: z.literal('reform-2026'),
  sourceRule: z.string(),
  severity: _severitySchema,
  category: z.string(),
  title: z.string(),
  description: z.string(),
  remediation: z.string(),
  file: z.string().optional(),
  line: z.number().optional(),
  provision: reformProvisionSchema,
  effectiveDate: z.string(),
  appMappings: z.array(_appMappingSchema),
});
export type ReformFinding = z.infer<typeof reformFindingSchema>;

// ─── Reform Impact Assessment ─────────────────────────────────────────────────

export const reformImpactAssessmentSchema = z.object({
  overallImpact: z.enum(['high', 'medium', 'low']),
  provisions: z.array(z.object({
    provision: reformProvisionSchema,
    status: z.enum(['compliant', 'gap', 'unknown']),
    findings: z.array(z.string()),
    effectiveDate: z.string(),
    summary: z.string(),
  })),
  actionItems: z.array(z.object({
    priority: z.enum(['immediate', 'before_deadline', 'recommended']),
    provision: reformProvisionSchema,
    title: z.string(),
    description: z.string(),
    deadline: z.string(),
  })),
  assessmentDate: z.string(),
  disclaimer: z.string(),
});
export type ReformImpactAssessment = z.infer<typeof reformImpactAssessmentSchema>;