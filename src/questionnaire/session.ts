import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

import { AnyQuestionnaireSession, QuestionnaireSession } from '../schema/index.js';
import type {
  AssessmentMode,
  APPPrinciple,
  AnyQuestionnaireSession as AnyQuestionnaireSessionType,
  AttestLensFinding,
  FrozenQuestionnaireSession,
  LegacyQuestionnaireSession,
  Question,
  QuestionnairePrincipleResult,
  QuestionnaireResponse,
  QuestionnaireSession as QuestionnaireSessionType,
  TransitionalQuestionnaireSession,
} from '../schema/index.js';
import {
  LEGACY_QUESTION_BANK_V1,
  LEGACY_QUESTIONNAIRE_VERSION,
  PRE_REMEDIATION_QUESTION_BANK_V2,
  PRE_REMEDIATION_QUESTIONNAIRE_VERSION,
  QUESTION_BANK,
  QUESTIONNAIRE_VERSION,
  getQuestionsForPrinciples,
} from './questions.js';
import { aggregatePrincipleResults } from './evaluator.js';
import { getNextQuestion } from './flow.js';

export type SessionTarget =
  | { kind: 'path'; name: string; path: string; url?: undefined }
  | { kind: 'url'; name: string; url: string; path?: undefined };

export interface SessionPaths {
  directory: string;
  sessionPath: string;
  scanSnapshotPath: string;
}

export interface PreparedQuestionnaireSession {
  session: QuestionnaireSessionType;
  didUpgrade: boolean;
}

const SESSION_INTEGRITY_FAILURE =
  'Attestation session integrity check failed. Start a new attestation session.';
const DEFAULT_ASSESSMENT_MODE: AssessmentMode = 'operator_attested';
const UPGRADE_ASSESSMENT_MODE_REQUIRED =
  'Pre-1.3 attestation sessions require an explicit assessment basis before they can be resumed.';

function slugifyTarget(targetName: string): string {
  return targetName
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80) || 'target';
}

function serializeQuestionForHash(question: Question): Record<string, unknown> {
  return {
    id: question.id,
    appPrinciple: question.appPrinciple,
    question: question.question,
    type: question.type,
    options: question.options,
    required: question.required,
    role: question.role,
    passOn: question.passOn,
    blocking: question.blocking,
    minimumSelectedOptions: question.minimumSelectedOptions,
    failOnOptions: question.failOnOptions,
    assessmentModes: question.assessmentModes,
    helpText: question.helpText,
    dependsOn: question.dependsOn ? {
      questionId: question.dependsOn.questionId,
      answers: [...question.dependsOn.answers],
    } : undefined,
    relatedFindings: question.relatedFindings,
  };
}

function questionsExactlyMatch(left: Question[], right: Question[]): boolean {
  if (left.length !== right.length) {
    return false;
  }

  return left.every((question, index) =>
    JSON.stringify(serializeQuestionForHash(question)) === JSON.stringify(serializeQuestionForHash(right[index]!)),
  );
}

function principlesExactlyMatch(left: APPPrinciple[], right: APPPrinciple[]): boolean {
  return left.length === right.length && left.every((principle, index) => principle === right[index]);
}

function getKnownQuestionBank(version: string): Question[] | null {
  if (version === QUESTIONNAIRE_VERSION) {
    return QUESTION_BANK;
  }

  if (version === PRE_REMEDIATION_QUESTIONNAIRE_VERSION) {
    return PRE_REMEDIATION_QUESTION_BANK_V2;
  }

  if (version === LEGACY_QUESTIONNAIRE_VERSION) {
    return LEGACY_QUESTION_BANK_V1;
  }

  return null;
}

function assertSessionQuestionRefs(
  session: Pick<QuestionnaireSessionType, 'answers' | 'currentQuestionId' | 'sessionQuestions'>,
): void {
  const questionIds = new Set(session.sessionQuestions.map((question) => question.id));

  for (const answer of session.answers) {
    if (!questionIds.has(answer.questionId)) {
      throw new Error(SESSION_INTEGRITY_FAILURE);
    }
  }

  if (session.currentQuestionId && !questionIds.has(session.currentQuestionId)) {
    throw new Error(SESSION_INTEGRITY_FAILURE);
  }
}

function buildLegacySessionPrinciples(
  session: LegacyQuestionnaireSession | FrozenQuestionnaireSession | QuestionnaireSessionType,
): APPPrinciple[] {
  const principleSet = new Set<APPPrinciple>(session.principleResults.map((result) => result.principle));

  for (const answer of session.answers) {
    const question = LEGACY_QUESTION_BANK_V1.find((candidate) => candidate.id === answer.questionId);
    if (question) {
      principleSet.add(question.appPrinciple);
    }
  }

  return Array.from(principleSet);
}

export function buildQuestionSetHash(params: {
  questionnaireVersion: string;
  findingsHash: string;
  principles: APPPrinciple[];
  sessionQuestions: Question[];
  assessmentMode?: AssessmentMode;
}): string {
  return crypto
    .createHash('sha256')
    .update(JSON.stringify({
      questionnaireVersion: params.questionnaireVersion,
      findingsHash: params.findingsHash,
      principles: [...params.principles],
      sessionQuestions: params.sessionQuestions.map((question) => serializeQuestionForHash(question)),
      assessmentMode: params.assessmentMode,
    }))
    .digest('hex')
    .substring(0, 32);
}

function normalizeFindingsHash(findingsHash: string, findings: AttestLensFinding[]): void {
  const recomputedFindingsHash = buildFindingsHash(findings);
  if (recomputedFindingsHash !== findingsHash) {
    throw new Error(SESSION_INTEGRITY_FAILURE);
  }
}

function upgradeLegacyQuestionnaireSession(
  session: LegacyQuestionnaireSession,
  findingsHash: string,
  assessmentMode: AssessmentMode,
): QuestionnaireSessionType {
  const principles = buildLegacySessionPrinciples(session);
  const sessionQuestions = buildFrozenSessionQuestions(principles, LEGACY_QUESTION_BANK_V1);
  return rebuildUpgradedQuestionnaireSession(session, {
    questionnaireVersion: LEGACY_QUESTIONNAIRE_VERSION,
    findingsHash,
    principles,
    sessionQuestions,
    assessmentMode,
  });
}

function upgradeCanonicalQuestionnaireSession(
  session: TransitionalQuestionnaireSession,
  findingsHash: string,
  expectedPrinciples: APPPrinciple[],
  expectedQuestions: Question[],
  assessmentMode: AssessmentMode,
): QuestionnaireSessionType {
  if (session.questionnaireVersion !== QUESTIONNAIRE_VERSION) {
    throw new Error(SESSION_INTEGRITY_FAILURE);
  }

  if (!principlesExactlyMatch(session.principles, expectedPrinciples)) {
    throw new Error(SESSION_INTEGRITY_FAILURE);
  }

  if (!questionsExactlyMatch(session.sessionQuestions, expectedQuestions)) {
    throw new Error(SESSION_INTEGRITY_FAILURE);
  }

  return rebuildUpgradedQuestionnaireSession(session, {
    questionnaireVersion: QUESTIONNAIRE_VERSION,
    findingsHash,
    principles: expectedPrinciples,
    sessionQuestions: expectedQuestions,
    assessmentMode,
  });
}

function upgradeFrozenQuestionnaireSession(
  session: FrozenQuestionnaireSession,
  findingsHash: string,
  expectedPrinciples: APPPrinciple[],
  expectedQuestions: Question[],
  assessmentMode: AssessmentMode,
): QuestionnaireSessionType {
  const knownQuestionBank = getKnownQuestionBank(session.questionnaireVersion);
  if (!knownQuestionBank) {
    throw new Error(SESSION_INTEGRITY_FAILURE);
  }

  if (!principlesExactlyMatch(session.principles, expectedPrinciples)) {
    throw new Error(SESSION_INTEGRITY_FAILURE);
  }

  const storedExpectedQuestions = buildFrozenSessionQuestions(expectedPrinciples, knownQuestionBank);
  if (!questionsExactlyMatch(session.sessionQuestions, storedExpectedQuestions)) {
    throw new Error(SESSION_INTEGRITY_FAILURE);
  }

  const storedExpectedHash = buildQuestionSetHash({
    questionnaireVersion: session.questionnaireVersion,
    findingsHash,
    principles: expectedPrinciples,
    sessionQuestions: storedExpectedQuestions,
  });

  if (session.questionSetHash !== storedExpectedHash) {
    throw new Error(SESSION_INTEGRITY_FAILURE);
  }

  return rebuildUpgradedQuestionnaireSession(session, {
    questionnaireVersion: QUESTIONNAIRE_VERSION,
    findingsHash,
    principles: expectedPrinciples,
    sessionQuestions: expectedQuestions,
    assessmentMode,
  });
}

function requireUpgradeAssessmentMode(assessmentMode?: AssessmentMode): AssessmentMode {
  if (!assessmentMode) {
    throw new Error(UPGRADE_ASSESSMENT_MODE_REQUIRED);
  }

  return assessmentMode;
}

function rebuildUpgradedQuestionnaireSession(
  session: LegacyQuestionnaireSession | TransitionalQuestionnaireSession | FrozenQuestionnaireSession,
  params: {
    questionnaireVersion: string;
    findingsHash: string;
    principles: APPPrinciple[];
    sessionQuestions: Question[];
    assessmentMode: AssessmentMode;
  },
): QuestionnaireSessionType {
  const principleResults = aggregatePrincipleResults(
    params.principles,
    session.answers,
    params.sessionQuestions,
    params.assessmentMode,
  );
  const currentQuestionId = session.status === 'completed'
    ? undefined
    : getNextQuestion(
      params.principles,
      session.answers,
      params.sessionQuestions,
      params.assessmentMode,
    )?.id;
  const upgraded: QuestionnaireSessionType = {
    ...session,
    version: '1.3',
    questionnaireVersion: params.questionnaireVersion,
    findingsHash: params.findingsHash,
    principles: params.principles,
    sessionQuestions: params.sessionQuestions,
    questionSetHash: buildQuestionSetHash({
      questionnaireVersion: params.questionnaireVersion,
      findingsHash: params.findingsHash,
      principles: params.principles,
      sessionQuestions: params.sessionQuestions,
      assessmentMode: params.assessmentMode,
    }),
    assessmentMode: params.assessmentMode,
    principleResults,
    currentQuestionId,
  };
  assertSessionQuestionRefs(upgraded);
  return upgraded;
}

function validateCurrentQuestionnaireSession(
  session: QuestionnaireSessionType,
  findingsHash: string,
  expectedPrinciples: APPPrinciple[],
  expectedQuestions: Question[],
): QuestionnaireSessionType {
  if (session.questionnaireVersion === QUESTIONNAIRE_VERSION) {
    if (!principlesExactlyMatch(session.principles, expectedPrinciples)) {
      throw new Error(SESSION_INTEGRITY_FAILURE);
    }

    if (!questionsExactlyMatch(session.sessionQuestions, expectedQuestions)) {
      throw new Error(SESSION_INTEGRITY_FAILURE);
    }

    const expectedHash = buildQuestionSetHash({
      questionnaireVersion: session.questionnaireVersion,
      findingsHash,
      principles: expectedPrinciples,
      sessionQuestions: expectedQuestions,
      assessmentMode: session.assessmentMode,
    });

    if (session.questionSetHash !== expectedHash) {
      throw new Error(SESSION_INTEGRITY_FAILURE);
    }

    const validated = {
      ...session,
      findingsHash,
      principles: expectedPrinciples,
      sessionQuestions: expectedQuestions,
      questionSetHash: expectedHash,
      assessmentMode: session.assessmentMode,
    };
    assertSessionQuestionRefs(validated);
    return validated;
  }

  if (session.questionnaireVersion === LEGACY_QUESTIONNAIRE_VERSION) {
    const expectedLegacyPrinciples = buildLegacySessionPrinciples(session);
    const expectedLegacyQuestions = buildFrozenSessionQuestions(expectedLegacyPrinciples, LEGACY_QUESTION_BANK_V1);
    if (!principlesExactlyMatch(session.principles, expectedLegacyPrinciples)) {
      throw new Error(SESSION_INTEGRITY_FAILURE);
    }

    if (!questionsExactlyMatch(session.sessionQuestions, expectedLegacyQuestions)) {
      throw new Error(SESSION_INTEGRITY_FAILURE);
    }

    const expectedHash = buildQuestionSetHash({
      questionnaireVersion: session.questionnaireVersion,
      findingsHash,
      principles: expectedLegacyPrinciples,
      sessionQuestions: expectedLegacyQuestions,
      assessmentMode: session.assessmentMode,
    });

    if (session.questionSetHash !== expectedHash) {
      throw new Error(SESSION_INTEGRITY_FAILURE);
    }

    const validated = {
      ...session,
      findingsHash,
      principles: expectedLegacyPrinciples,
      sessionQuestions: expectedLegacyQuestions,
      questionSetHash: expectedHash,
      assessmentMode: session.assessmentMode,
    };
    assertSessionQuestionRefs(validated);
    return validated;
  }

  if (!getKnownQuestionBank(session.questionnaireVersion)) {
    throw new Error(SESSION_INTEGRITY_FAILURE);
  }

  throw new Error(SESSION_INTEGRITY_FAILURE);
}

export function prepareQuestionnaireSessionForResume(params: {
  session: AnyQuestionnaireSessionType;
  findings: AttestLensFinding[];
  expectedPrinciples: APPPrinciple[];
  expectedQuestions: Question[];
  upgradeAssessmentMode?: AssessmentMode;
}): PreparedQuestionnaireSession {
  normalizeFindingsHash(params.session.findingsHash, params.findings);
  const findingsHash = buildFindingsHash(params.findings);

  if (params.session.version === '1.0') {
    return {
      session: upgradeLegacyQuestionnaireSession(
        params.session,
        findingsHash,
        requireUpgradeAssessmentMode(params.upgradeAssessmentMode),
      ),
      didUpgrade: true,
    };
  }

  if (params.session.version === '1.1') {
    return {
      session: upgradeCanonicalQuestionnaireSession(
        params.session,
        findingsHash,
        params.expectedPrinciples,
        params.expectedQuestions,
        requireUpgradeAssessmentMode(params.upgradeAssessmentMode),
      ),
      didUpgrade: true,
    };
  }

  if (params.session.version === '1.2') {
    return {
      session: upgradeFrozenQuestionnaireSession(
        params.session,
        findingsHash,
        params.expectedPrinciples,
        params.expectedQuestions,
        requireUpgradeAssessmentMode(params.upgradeAssessmentMode),
      ),
      didUpgrade: true,
    };
  }

  return {
    session: validateCurrentQuestionnaireSession(
      params.session,
      findingsHash,
      params.expectedPrinciples,
      params.expectedQuestions,
    ),
    didUpgrade: false,
  };
}

export function buildSessionPaths(outputDir: string, targetName: string, sessionId: string): SessionPaths {
  const directory = path.join(path.resolve(outputDir), 'attest', slugifyTarget(targetName), sessionId);
  return {
    directory,
    sessionPath: path.join(directory, 'session.json'),
    scanSnapshotPath: path.join(directory, 'scan-results.json'),
  };
}

export function buildFindingsHash(findings: AttestLensFinding[]): string {
  return crypto
    .createHash('sha256')
    .update(JSON.stringify(findings.map((finding) => finding.id).sort()))
    .digest('hex')
    .substring(0, 32);
}

export function buildFrozenSessionQuestions(
  principles: APPPrinciple[],
  questions: Question[] = QUESTION_BANK,
): Question[] {
  return getQuestionsForPrinciples(principles, questions);
}

export function createQuestionnaireSession(params: {
  id?: string;
  target: SessionTarget;
  strictMode: boolean;
  scanSnapshotPath: string;
  findingsHash: string;
  questionnaireVersion: string;
  principles: APPPrinciple[];
  sessionQuestions: Question[];
  principleResults: QuestionnairePrincipleResult[];
  assessmentMode: AssessmentMode;
  currentQuestionId?: string;
}): QuestionnaireSessionType {
  const now = new Date().toISOString();
  const questionSetHash = buildQuestionSetHash({
    questionnaireVersion: params.questionnaireVersion,
    findingsHash: params.findingsHash,
    principles: params.principles,
    sessionQuestions: params.sessionQuestions,
    assessmentMode: params.assessmentMode,
  });
  return {
    id: params.id || crypto.randomUUID(),
    version: '1.3',
    questionnaireVersion: params.questionnaireVersion,
    status: 'in_progress',
    target: params.target,
    startedAt: now,
    updatedAt: now,
    strictMode: params.strictMode,
    scanSnapshotPath: params.scanSnapshotPath,
    findingsHash: params.findingsHash,
    principles: params.principles,
    sessionQuestions: params.sessionQuestions,
    questionSetHash,
    assessmentMode: params.assessmentMode,
    answers: [],
    principleResults: params.principleResults,
    currentQuestionId: params.currentQuestionId,
  };
}

export async function ensureSessionDirectory(paths: SessionPaths): Promise<void> {
  await fs.mkdir(paths.directory, { recursive: true });
}

export async function saveQuestionnaireSession(session: QuestionnaireSessionType, sessionPath: string): Promise<void> {
  const normalizedSession = QuestionnaireSession.parse({
    ...session,
    updatedAt: new Date().toISOString(),
  });
  await fs.writeFile(sessionPath, JSON.stringify(normalizedSession, null, 2));
}

export async function loadQuestionnaireSession(sessionPath: string): Promise<AnyQuestionnaireSessionType> {
  const raw = JSON.parse(await fs.readFile(path.resolve(sessionPath), 'utf-8'));
  return AnyQuestionnaireSession.parse(raw);
}

export async function writeScanSnapshot(snapshotPath: string, payload: unknown): Promise<void> {
  await fs.writeFile(snapshotPath, JSON.stringify(payload, null, 2));
}

export async function loadScanSnapshot<T>(snapshotPath: string): Promise<T> {
  return JSON.parse(await fs.readFile(path.resolve(snapshotPath), 'utf-8')) as T;
}

export function updateSessionProgress(
  session: QuestionnaireSessionType,
  answers: QuestionnaireResponse[],
  principleResults: QuestionnairePrincipleResult[],
  currentQuestionId?: string,
): QuestionnaireSessionType {
  return {
    ...session,
    answers,
    principleResults,
    currentQuestionId,
    updatedAt: new Date().toISOString(),
  };
}

export function completeQuestionnaireSession(
  session: QuestionnaireSessionType,
  answers: QuestionnaireResponse[],
  principleResults: QuestionnairePrincipleResult[],
): QuestionnaireSessionType {
  const now = new Date().toISOString();
  return {
    ...session,
    status: 'completed',
    answers,
    principleResults,
    currentQuestionId: undefined,
    updatedAt: now,
    completedAt: now,
  };
}

export {
  LEGACY_QUESTIONNAIRE_VERSION,
  PRE_REMEDIATION_QUESTIONNAIRE_VERSION,
  QUESTIONNAIRE_VERSION,
  SESSION_INTEGRITY_FAILURE,
  UPGRADE_ASSESSMENT_MODE_REQUIRED,
};
