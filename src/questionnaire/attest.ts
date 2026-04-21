import crypto from 'node:crypto';

import { mapAllFindings } from '../mapping/engine.js';
import type {
  APPPrinciple,
  AttestLensFinding,
  QuestionnaireResponse,
  QuestionnaireSession,
} from '../schema/index.js';
import type { ScannerError, ScannerResult } from '../scanner/types.js';
import { aggregatePrincipleResults, evaluateResponse } from './evaluator.js';
import { getApplicableQuestions, getNextQuestion } from './flow.js';
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
}

export interface InitializedAttestationSession {
  session: QuestionnaireSession;
  paths: SessionPaths;
  principles: APPPrinciple[];
}

export interface QuestionProgress {
  current: number;
  total: number;
}

export type AttestationRunResult =
  | {
      status: 'saved';
      session: QuestionnaireSession;
      principles: APPPrinciple[];
      progress: QuestionProgress;
    }
  | {
      status: 'completed';
      session: QuestionnaireSession;
      principles: APPPrinciple[];
      progress: QuestionProgress;
    };

export function buildAttestationScanSnapshot(params: {
  target: SessionTarget;
  findings: AttestLensFinding[];
  results?: ScannerResult[];
  errors?: ScannerError[];
  totalDurationMs?: number;
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
  };
}

export function deriveQuestionnairePrinciples(findings: AttestLensFinding[]): APPPrinciple[] {
  const { controls } = mapAllFindings(findings, false);
  return controls
    .filter((control) => control.questionnaireRequired)
    .map((control) => control.principle);
}

function buildRelevantFindings(
  findings: AttestLensFinding[],
  principle: APPPrinciple,
): AttestLensFinding[] {
  mapAllFindings(findings, false);

  return findings.filter((finding) =>
    finding.appMappings.some((mapping) => mapping.principle === principle),
  );
}

function buildProgress(
  principles: APPPrinciple[],
  responses: QuestionnaireResponse[],
  sessionQuestions = buildFrozenSessionQuestions(principles),
): QuestionProgress {
  const applicableQuestions = getApplicableQuestions(
    sessionQuestions.filter((question) => principles.includes(question.appPrinciple)),
    responses,
  );
  const total = applicableQuestions.length;
  const answeredIds = new Set(responses.map((response) => response.questionId));
  const answered = applicableQuestions.filter((question) => answeredIds.has(question.id)).length;

  return {
    current: Math.min(answered + 1, Math.max(total, 1)),
    total: Math.max(total, 1),
  };
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
}): Promise<InitializedAttestationSession> {
  const sessionId = crypto.randomUUID();
  const paths = buildSessionPaths(params.outputDir, params.target.name, sessionId);
  await ensureSessionDirectory(paths);
  await writeScanSnapshot(paths.scanSnapshotPath, params.snapshot);

  const principles = deriveQuestionnairePrinciples(params.snapshot.findings);
  const sessionQuestions = buildFrozenSessionQuestions(principles);
  const principleResults = aggregatePrincipleResults(principles, [], sessionQuestions);
  const currentQuestionId = getNextQuestion(principles, [], sessionQuestions)?.id;
  const session = createQuestionnaireSession({
    id: sessionId,
    target: params.target,
    strictMode: params.strictMode,
    scanSnapshotPath: paths.scanSnapshotPath,
    findingsHash: buildFindingsHash(params.snapshot.findings),
    questionnaireVersion: QUESTIONNAIRE_VERSION,
    principles,
    sessionQuestions,
    principleResults,
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
  let session = params.session;
  let answers = session.answers;

  while (true) {
    const principleResults = aggregatePrincipleResults(principles, answers, sessionQuestions);
    const nextQuestion = getNextQuestion(principles, answers, sessionQuestions);

    if (!nextQuestion) {
      session = completeQuestionnaireSession(session, answers, principleResults);
      await saveQuestionnaireSession(session, params.sessionPath);
      return {
        status: 'completed',
        session,
        principles,
        progress: buildProgress(principles, answers, sessionQuestions),
      };
    }

    session = updateSessionProgress(session, answers, principleResults, nextQuestion.id);
    await saveQuestionnaireSession(session, params.sessionPath);

    const progress = buildProgress(principles, answers, sessionQuestions);
    const promptResult = await params.promptRunner.prompt(nextQuestion, {
      progress,
      sessionPath: params.sessionPath,
      relevantFindings: buildRelevantFindings(params.snapshot.findings, nextQuestion.appPrinciple),
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
    const nextPrincipleResults = aggregatePrincipleResults(principles, answers, sessionQuestions);
    const nextQuestionId = getNextQuestion(principles, answers, sessionQuestions)?.id;

    session = updateSessionProgress(session, answers, nextPrincipleResults, nextQuestionId);
    await saveQuestionnaireSession(session, params.sessionPath);
  }
}
