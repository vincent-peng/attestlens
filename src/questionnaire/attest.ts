import crypto from 'node:crypto';

import { mapAllFindings } from '../mapping/engine.js';
import { RuleFreshness as RuleFreshnessSchema } from '../schema/index.js';
import type {
  AssessmentMode,
  AttestLensFinding,
  Jurisdiction,
  QuestionnaireResponse,
  QuestionnaireSession,
  RegulationPrinciple,
  RuleFreshness,
} from '../schema/index.js';
import type { ScannerError, ScannerResult } from '../scanner/types.js';
import { aggregatePrincipleResults, evaluateResponse } from './evaluator.js';
import { getApplicableQuestions, getNextQuestion, getQuestionBankForJurisdiction } from './flow.js';
import { CCPA_QUESTIONNAIRE_VERSION } from './ccpa-questions.js';
import { GDPR_QUESTIONNAIRE_VERSION } from './gdpr-questions.js';
import type { AttestationPromptRunner } from './prompts.js';
import {
  QUESTIONNAIRE_VERSION,
  buildFrozenSessionQuestions,
  buildFindingsHash,
  buildSessionPaths,
  completeQuestionnaireSession,
  createQuestionnaireSession,
  ensureSessionDirectory,
  saveQuestionnaireSession,
  updateSessionProgress,
  writeScanSnapshot,
  type SessionPaths,
  type SessionTarget,
} from './session.js';

export interface AttestationScanSnapshot {
  targetType: 'path' | 'url';
  target: {
    name: string;
    path?: string;
    url?: string;
  };
  targetPath?: string;
  targetUrl?: string;
  findings: AttestLensFinding[];
  results: ScannerResult[];
  errors: ScannerError[];
  totalDurationMs: number;
  ruleFreshness?: RuleFreshness;
  jurisdiction?: Jurisdiction;
}

export interface InitializedAttestationSession {
  session: QuestionnaireSession;
  paths: SessionPaths;
  principles: RegulationPrinciple[];
}

export interface QuestionProgress {
  current: number;
  total: number;
}

export type AttestationRunResult =
  | {
      status: 'saved';
      session: QuestionnaireSession;
      principles: RegulationPrinciple[];
      progress: QuestionProgress;
    }
  | {
      status: 'completed';
      session: QuestionnaireSession;
      principles: RegulationPrinciple[];
      progress: QuestionProgress;
    };

export function buildAttestationScanSnapshot(params: {
  target: SessionTarget;
  findings: AttestLensFinding[];
  results?: ScannerResult[];
  errors?: ScannerError[];
  totalDurationMs?: number;
  ruleFreshness?: RuleFreshness;
  jurisdiction?: Jurisdiction;
}): AttestationScanSnapshot {
  return {
    targetType: params.target.kind,
    target: {
      name: params.target.name,
      path: params.target.path,
      url: params.target.url,
    },
    targetPath: params.target.path,
    targetUrl: params.target.url,
    findings: params.findings,
    results: params.results || [],
    errors: params.errors || [],
    totalDurationMs: params.totalDurationMs ?? 0,
    ruleFreshness: params.ruleFreshness ? RuleFreshnessSchema.parse(params.ruleFreshness) : undefined,
    jurisdiction: params.jurisdiction,
  };
}

export function deriveQuestionnairePrinciples(
  findings: AttestLensFinding[],
  jurisdiction: Jurisdiction = 'au-privacy-act',
): RegulationPrinciple[] {
  const { controls } = mapAllFindings(findings, {
    strictMode: false,
    jurisdictions: [jurisdiction],
  });
  return controls
    .filter((control) => control.questionnaireRequired)
    .map((control) => control.principle);
}

function buildRelevantFindings(
  findings: AttestLensFinding[],
  principle: RegulationPrinciple,
  jurisdiction: Jurisdiction,
): AttestLensFinding[] {
  mapAllFindings(findings, {
    strictMode: false,
    jurisdictions: [jurisdiction],
  });

  return findings.filter((finding) =>
    finding.regulationMappings?.some((mapping) =>
      mapping.jurisdiction === jurisdiction && mapping.principle === principle,
    ) || finding.appMappings.some((mapping) => mapping.principle === principle),
  );
}

function buildProgress(
  principles: RegulationPrinciple[],
  responses: QuestionnaireResponse[],
  assessmentMode: AssessmentMode,
  sessionQuestions = buildFrozenSessionQuestions(principles),
): QuestionProgress {
  const applicableQuestions = getApplicableQuestions(
    sessionQuestions.filter((question) => principles.includes(question.regulationPrinciple)),
    responses,
    assessmentMode,
  );
  const total = applicableQuestions.length;
  const answeredIds = new Set(responses.map((response) => response.questionId));
  const answered = applicableQuestions.filter((question) => answeredIds.has(question.id)).length;

  return {
    current: Math.min(answered + 1, Math.max(total, 1)),
    total: Math.max(total, 1),
  };
}

function inferQuestionnaireJurisdiction(principles: RegulationPrinciple[]): Jurisdiction {
  if (principles.some((principle) => principle.startsWith('CCPA_'))) {
    return 'us-ccpa';
  }
  if (principles.some((principle) => principle.startsWith('GDPR_'))) {
    return 'eu-gdpr';
  }
  return 'au-privacy-act';
}

function getQuestionnaireVersionForJurisdiction(jurisdiction: Jurisdiction): string {
  if (jurisdiction === 'us-ccpa') {
    return CCPA_QUESTIONNAIRE_VERSION;
  }
  if (jurisdiction === 'eu-gdpr') {
    return GDPR_QUESTIONNAIRE_VERSION;
  }
  return QUESTIONNAIRE_VERSION;
}

function buildResponse(
  promptResult: Extract<Awaited<ReturnType<AttestationPromptRunner['prompt']>>, { kind: 'answer' }>,
  questionId: string,
): QuestionnaireResponse {
  return {
    questionId,
    answer: promptResult.answer,
    timestamp: new Date().toISOString(),
    answeredBy: promptResult.answeredBy,
    note: promptResult.note,
    evidenceRefs: promptResult.evidenceRefs,
  };
}

export async function initializeAttestationSession(params: {
  snapshot: AttestationScanSnapshot;
  target: SessionTarget;
  outputDir: string;
  strictMode: boolean;
  assessmentMode: AssessmentMode;
  jurisdiction?: Jurisdiction;
}): Promise<InitializedAttestationSession> {
  const sessionId = crypto.randomUUID();
  const jurisdiction = params.jurisdiction ?? params.snapshot.jurisdiction ?? 'au-privacy-act';
  const paths = buildSessionPaths(params.outputDir, params.target.name, sessionId);
  await ensureSessionDirectory(paths);
  await writeScanSnapshot(paths.scanSnapshotPath, {
    ...params.snapshot,
    jurisdiction,
  });

  const principles = deriveQuestionnairePrinciples(params.snapshot.findings, jurisdiction);
  const questionBank = getQuestionBankForJurisdiction(jurisdiction);
  const sessionQuestions = buildFrozenSessionQuestions(principles, questionBank);
  const principleResults = aggregatePrincipleResults(principles, [], sessionQuestions, params.assessmentMode);
  const currentQuestionId = getNextQuestion(principles, [], sessionQuestions, params.assessmentMode, jurisdiction)?.id;
  const session = createQuestionnaireSession({
    id: sessionId,
    target: params.target,
    strictMode: params.strictMode,
    scanSnapshotPath: paths.scanSnapshotPath,
    findingsHash: buildFindingsHash(params.snapshot.findings),
    questionnaireVersion: getQuestionnaireVersionForJurisdiction(jurisdiction),
    principles,
    sessionQuestions,
    principleResults,
    assessmentMode: params.assessmentMode,
    currentQuestionId,
  });

  await saveQuestionnaireSession(session, paths.sessionPath);
  return {
    session,
    paths,
    principles,
  };
}

export async function runAttestationSession(params: {
  session: QuestionnaireSession;
  sessionPath: string;
  snapshot: AttestationScanSnapshot;
  promptRunner: AttestationPromptRunner;
}): Promise<AttestationRunResult> {
  const principles = params.session.principles;
  const sessionQuestions = params.session.sessionQuestions;
  const assessmentMode = params.session.assessmentMode;
  const jurisdiction = params.snapshot.jurisdiction ?? inferQuestionnaireJurisdiction(principles);
  let session = params.session;
  let answers = session.answers;

  while (true) {
    const principleResults = aggregatePrincipleResults(principles, answers, sessionQuestions, assessmentMode);
    const nextQuestion = getNextQuestion(principles, answers, sessionQuestions, assessmentMode, jurisdiction);

    if (!nextQuestion) {
      session = completeQuestionnaireSession(session, answers, principleResults);
      await saveQuestionnaireSession(session, params.sessionPath);
      return {
        status: 'completed',
        session,
        principles,
        progress: buildProgress(principles, answers, assessmentMode, sessionQuestions),
      };
    }

    session = updateSessionProgress(session, answers, principleResults, nextQuestion.id);
    await saveQuestionnaireSession(session, params.sessionPath);

    const progress = buildProgress(principles, answers, assessmentMode, sessionQuestions);
    const promptResult = await params.promptRunner.prompt(nextQuestion, {
      progress,
      sessionPath: params.sessionPath,
      relevantFindings: buildRelevantFindings(params.snapshot.findings, nextQuestion.regulationPrinciple, jurisdiction),
    });

    if (promptResult.kind === 'save_and_exit') {
      return {
        status: 'saved',
        session,
        principles,
        progress,
      };
    }

    const response = buildResponse(promptResult, nextQuestion.id);
    const evaluatedResponse: QuestionnaireResponse = {
      ...response,
      evaluation: evaluateResponse(nextQuestion, response),
    };

    answers = [...answers, evaluatedResponse];
    const nextPrincipleResults = aggregatePrincipleResults(principles, answers, sessionQuestions, assessmentMode);
    const nextQuestionId = getNextQuestion(principles, answers, sessionQuestions, assessmentMode, jurisdiction)?.id;

    session = updateSessionProgress(session, answers, nextPrincipleResults, nextQuestionId);
    await saveQuestionnaireSession(session, params.sessionPath);
  }
}
