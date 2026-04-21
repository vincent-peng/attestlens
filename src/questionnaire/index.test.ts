import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import type {
  AttestLensFinding,
  LegacyQuestionnaireSession,
  Question,
  QuestionnaireResponse,
  QuestionnaireSession,
} from '../schema/index.js';
import {
  LEGACY_QUESTION_BANK_V1,
  LEGACY_QUESTIONNAIRE_VERSION,
  QUESTION_BANK,
  QUESTIONNAIRE_VERSION,
  aggregatePrincipleResults,
  buildFindingsHash,
  buildFrozenSessionQuestions,
  buildQuestionSetHash,
  buildSessionPaths,
  createQuestionnaireSession,
  evaluateResponse,
  getApplicableQuestionsForPrinciple,
  loadQuestionnaireSession,
  prepareQuestionnaireSessionForResume,
  saveQuestionnaireSession,
} from './index.js';

const tempDirs: string[] = [];

function makeResponse(
  questionId: string,
  answer: QuestionnaireResponse['answer'],
): QuestionnaireResponse {
  return {
    questionId,
    answer,
    timestamp: new Date().toISOString(),
  };
}

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((directory) => fs.rm(directory, { recursive: true, force: true })));
});

function makeCurrentSession(
  overrides: Partial<QuestionnaireSession> = {},
): QuestionnaireSession {
  const principles = overrides.principles || ['APP_1'];
  const findingsHash = overrides.findingsHash || buildFindingsHash([]);
  const questionnaireVersion = overrides.questionnaireVersion || QUESTIONNAIRE_VERSION;
  const sessionQuestions = overrides.sessionQuestions || buildFrozenSessionQuestions(principles);

  return {
    id: overrides.id || 'session-001',
    version: '1.2',
    questionnaireVersion,
    status: overrides.status || 'in_progress',
    target: overrides.target || {
      kind: 'path',
      name: 'Example App',
      path: '/tmp/example-app',
    },
    startedAt: overrides.startedAt || new Date().toISOString(),
    updatedAt: overrides.updatedAt || new Date().toISOString(),
    completedAt: overrides.completedAt,
    strictMode: overrides.strictMode ?? false,
    scanSnapshotPath: overrides.scanSnapshotPath || '/tmp/example-app/scan-results.json',
    findingsHash,
    principles,
    sessionQuestions,
    questionSetHash: overrides.questionSetHash || buildQuestionSetHash({
      questionnaireVersion,
      findingsHash,
      principles,
      sessionQuestions,
    }),
    answers: overrides.answers || [],
    principleResults: overrides.principleResults || aggregatePrincipleResults(principles, [], sessionQuestions),
    currentQuestionId: overrides.currentQuestionId,
  };
}

describe('question bank coverage and flow', () => {
  it('covers every APP/NDB principle with at least one question', () => {
    const coveredPrinciples = new Set(QUESTION_BANK.map((question) => question.appPrinciple));
    expect(Array.from(coveredPrinciples).sort()).toEqual([
      'APP_1',
      'APP_10',
      'APP_11',
      'APP_12',
      'APP_13',
      'APP_2',
      'APP_3',
      'APP_4',
      'APP_5',
      'APP_6',
      'APP_7',
      'APP_8',
      'APP_9',
      'NDB',
    ]);
  });

  it('skips APP 7 follow-ups when direct marketing is not used', () => {
    const withoutMarketing = getApplicableQuestionsForPrinciple('APP_7', []);
    expect(withoutMarketing.map((question) => question.id)).toEqual(['Q-APP7-001']);

    const withNoMarketing = getApplicableQuestionsForPrinciple('APP_7', [
      makeResponse('Q-APP7-001', false),
    ]);
    expect(withNoMarketing.map((question) => question.id)).toEqual(['Q-APP7-001']);

    const withMarketing = getApplicableQuestionsForPrinciple('APP_7', [
      makeResponse('Q-APP7-001', true),
    ]);
    expect(withMarketing.map((question) => question.id)).toEqual([
      'Q-APP7-001',
      'Q-APP7-002',
      'Q-APP7-003',
    ]);
  });

  it('treats APP 8 no-overseas-disclosure as a gate that skips follow-ups', () => {
    const withoutDisclosure = getApplicableQuestionsForPrinciple('APP_8', []);
    expect(withoutDisclosure.map((question) => question.id)).toEqual(['Q-APP8-001']);

    const withNoDisclosure = getApplicableQuestionsForPrinciple('APP_8', [
      makeResponse('Q-APP8-001', false),
    ]);
    expect(withNoDisclosure.map((question) => question.id)).toEqual(['Q-APP8-001']);

    const withDisclosure = getApplicableQuestionsForPrinciple('APP_8', [
      makeResponse('Q-APP8-001', true),
    ]);
    expect(withDisclosure.map((question) => question.id)).toEqual([
      'Q-APP8-001',
      'Q-APP8-002',
      'Q-APP8-003',
    ]);
  });

  it('skips APP 9 follow-ups when government identifiers are not handled', () => {
    const withNoGovIds = getApplicableQuestionsForPrinciple('APP_9', [
      makeResponse('Q-APP9-001', false),
    ]);
    expect(withNoGovIds.map((question) => question.id)).toEqual(['Q-APP9-001']);
  });

  it('adds APP 5 indirect collection follow-up only when the gate is triggered', () => {
    const directOnly = getApplicableQuestionsForPrinciple('APP_5', [
      makeResponse('Q-APP5-003', false),
    ]);
    expect(directOnly.map((question) => question.id)).toEqual([
      'Q-APP5-001',
      'Q-APP5-003',
    ]);

    const indirectCollection = getApplicableQuestionsForPrinciple('APP_5', [
      makeResponse('Q-APP5-003', true),
    ]);
    expect(indirectCollection.map((question) => question.id)).toEqual([
      'Q-APP5-001',
      'Q-APP5-003',
      'Q-APP5-002',
    ]);
  });

  it('gates APP 2 follow-up questions behind the anonymity exception path', () => {
    const anonymousFlow = getApplicableQuestionsForPrinciple('APP_2', [
      makeResponse('Q-APP2-001', true),
    ]);
    expect(anonymousFlow.map((question) => question.id)).toEqual(['Q-APP2-001']);

    const identifiedFlow = getApplicableQuestionsForPrinciple('APP_2', [
      makeResponse('Q-APP2-001', false),
    ]);
    expect(identifiedFlow.map((question) => question.id)).toEqual([
      'Q-APP2-001',
      'Q-APP2-002',
    ]);
  });
});

describe('questionnaire evaluator', () => {
  it('marks fully answered blocking questions as pass', () => {
    const result = aggregatePrincipleResults(['APP_1'], [
      makeResponse('Q-APP1-001', true),
      makeResponse('Q-APP1-002', true),
    ])[0];

    expect(result).toMatchObject({
      principle: 'APP_1',
      status: 'pass',
    });
  });

  it('marks a principle as fail when a blocking answer fails', () => {
    const result = aggregatePrincipleResults(['APP_1'], [
      makeResponse('Q-APP1-001', true),
      makeResponse('Q-APP1-002', false),
    ])[0];

    expect(result).toMatchObject({
      principle: 'APP_1',
      status: 'fail',
    });
  });

  it('keeps a principle unknown when applicable blocking answers are missing', () => {
    const result = aggregatePrincipleResults(['APP_1'], [
      makeResponse('Q-APP1-001', true),
    ])[0];

    expect(result).toMatchObject({
      principle: 'APP_1',
      status: 'unknown',
    });
  });

  it('does not fail a principle when an optional evidence question is answered negatively', () => {
    const result = aggregatePrincipleResults(['APP_1'], [
      makeResponse('Q-APP1-001', true),
      makeResponse('Q-APP1-002', true),
      makeResponse('Q-APP1-003', false),
    ])[0];

    expect(result.status).toBe('pass');
  });

  it('keeps free-text answers unresolved and applies an evidence confidence boost to binary answers', () => {
    const textQuestion: Question = {
      id: 'Q-TEXT-001',
      appPrinciple: 'APP_1',
      question: 'Provide your policy rationale',
      type: 'text',
      required: true,
    };
    const textResponse = evaluateResponse(textQuestion, {
      ...makeResponse('Q-TEXT-001', 'Documented internally'),
      note: 'Reviewed by privacy lead',
    });

    expect(textResponse.status).toBe('unknown');

    const binaryQuestion: Question = {
      id: 'Q-YESNO-001',
      appPrinciple: 'APP_1',
      question: 'Is the policy public?',
      type: 'yes_no',
      required: true,
      role: 'control',
      passOn: 'yes',
      blocking: true,
    };
    const binaryResponse = evaluateResponse(binaryQuestion, {
      ...makeResponse('Q-YESNO-001', true),
      note: 'Published on website',
      evidenceRefs: ['docs/privacy-policy.md'],
    });

    expect(binaryResponse.status).toBe('pass');
    expect(binaryResponse.confidence).toBeGreaterThan(0.8);
  });

  it('treats APP 8 no-overseas-disclosure as pass with no follow-up failure', () => {
    const result = aggregatePrincipleResults(['APP_8'], [
      makeResponse('Q-APP8-001', false),
    ])[0];

    expect(result).toMatchObject({
      principle: 'APP_8',
      status: 'pass',
    });
  });

  it('fails the NDB procedure checklist when the minimum coverage is not met', () => {
    const result = aggregatePrincipleResults(['NDB'], [
      makeResponse('Q-NDB-001', true),
      makeResponse('Q-NDB-002', ['Assessing eligible data breaches', 'Containing breaches']),
      makeResponse('Q-NDB-003', true),
      makeResponse('Q-NDB-004', true),
    ])[0];

    expect(result).toMatchObject({
      principle: 'NDB',
      status: 'fail',
    });
  });

  it('marks APP 2 as pass when anonymity is available and skips the exception control', () => {
    const result = aggregatePrincipleResults(['APP_2'], [
      makeResponse('Q-APP2-001', true),
    ])[0];

    expect(result).toMatchObject({
      principle: 'APP_2',
      status: 'pass',
    });
  });

  it('keeps APP 2 unknown until the exception control is answered when anonymity is not available', () => {
    const result = aggregatePrincipleResults(['APP_2'], [
      makeResponse('Q-APP2-001', false),
    ])[0];

    expect(result).toMatchObject({
      principle: 'APP_2',
      status: 'unknown',
    });
  });

  it('marks APP 2 pass when the identification exception is documented', () => {
    const result = aggregatePrincipleResults(['APP_2'], [
      makeResponse('Q-APP2-001', false),
      makeResponse('Q-APP2-002', true),
    ])[0];

    expect(result).toMatchObject({
      principle: 'APP_2',
      status: 'pass',
    });
  });

  it('marks APP 2 fail when the identification exception is not documented', () => {
    const result = aggregatePrincipleResults(['APP_2'], [
      makeResponse('Q-APP2-001', false),
      makeResponse('Q-APP2-002', false),
    ])[0];

    expect(result).toMatchObject({
      principle: 'APP_2',
      status: 'fail',
    });
  });
});

describe('questionnaire session persistence', () => {
  it('round-trips a 1.2 session through session.json with frozen question metadata and integrity hash', async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-questionnaire-'));
    tempDirs.push(tempDir);

    const paths = buildSessionPaths(tempDir, 'Example App', 'session-123');
    await fs.mkdir(paths.directory, { recursive: true });

    const principles = ['APP_1'] as const;
    const principleResults = aggregatePrincipleResults([...principles], []);
    const session = createQuestionnaireSession({
      id: 'session-123',
      target: {
        kind: 'path',
        name: 'Example App',
        path: '/tmp/example-app',
      },
      strictMode: true,
      scanSnapshotPath: paths.scanSnapshotPath,
      findingsHash: buildFindingsHash([]),
      questionnaireVersion: QUESTIONNAIRE_VERSION,
      principles: [...principles],
      sessionQuestions: buildFrozenSessionQuestions([...principles]),
      principleResults,
      currentQuestionId: 'Q-APP1-001',
    });

    await saveQuestionnaireSession(session, paths.sessionPath);
    const loaded = await loadQuestionnaireSession(paths.sessionPath);

    expect(loaded.version).toBe('1.2');
    if (loaded.version !== '1.2') {
      throw new Error('Expected a 1.2 questionnaire session');
    }

    expect(loaded).toEqual<QuestionnaireSession>({
      ...session,
      updatedAt: loaded.updatedAt,
    });
    expect(loaded.questionnaireVersion).toBe(QUESTIONNAIRE_VERSION);
    expect(loaded.principles).toEqual(['APP_1']);
    expect(loaded.sessionQuestions.map((question) => question.id)).toEqual([
      'Q-APP1-001',
      'Q-APP1-002',
      'Q-APP1-003',
    ]);
    expect(loaded.questionSetHash).toBeTruthy();
  });

  it('validates a canonical 1.2 session against the frozen snapshot', () => {
    const session = makeCurrentSession({
      principles: ['APP_1'],
      currentQuestionId: 'Q-APP1-001',
    });

    const prepared = prepareQuestionnaireSessionForResume({
      session,
      findings: [],
      expectedPrinciples: ['APP_1'],
      expectedQuestions: buildFrozenSessionQuestions(['APP_1']),
    });

    expect(prepared.didUpgrade).toBe(false);
    expect(prepared.session.version).toBe('1.2');
  });

  it('rejects tampered 1.2 sessions when frozen questions no longer match the canonical set', () => {
    const session = makeCurrentSession({
      principles: ['APP_1'],
      sessionQuestions: buildFrozenSessionQuestions(['APP_1']).filter((question) => question.id !== 'Q-APP1-002'),
    });

    expect(() => prepareQuestionnaireSessionForResume({
      session,
      findings: [],
      expectedPrinciples: ['APP_1'],
      expectedQuestions: buildFrozenSessionQuestions(['APP_1']),
    })).toThrow(/integrity check failed/i);
  });

  it('rejects tampered 1.2 sessions when the principles no longer match the frozen snapshot', () => {
    const session = makeCurrentSession({
      principles: ['APP_1'],
      sessionQuestions: buildFrozenSessionQuestions(['APP_1']),
    });

    expect(() => prepareQuestionnaireSessionForResume({
      session,
      findings: [],
      expectedPrinciples: ['APP_1', 'APP_2'],
      expectedQuestions: buildFrozenSessionQuestions(['APP_1', 'APP_2']),
    })).toThrow(/integrity check failed/i);
  });

  it('rejects 1.2 resumes when the frozen scan findings hash no longer matches', () => {
    const session = makeCurrentSession({
      findingsHash: buildFindingsHash([]),
    });
    const findings: AttestLensFinding[] = [{
      id: 'FIND-001',
      source: 'guardvibe',
      sourceRule: 'VS-HARDKEY',
      severity: 'high',
      category: 'Security',
      title: 'Hardcoded secret',
      description: 'Detected secret in source',
      appMappings: [],
      evidence: {
        timestamp: new Date().toISOString(),
        scannerVersion: '0.1.0',
        rawOutput: {},
      },
    }];

    expect(() => prepareQuestionnaireSessionForResume({
      session,
      findings,
      expectedPrinciples: [],
      expectedQuestions: [],
    })).toThrow(/integrity check failed/i);
  });

  it('upgrades canonical 1.1 sessions to 1.2 only when they exactly match the canonical frozen set', () => {
    const principles = ['APP_1'] as const;
    const sessionQuestions = buildFrozenSessionQuestions([...principles]);
    const findingsHash = buildFindingsHash([]);
    const transitionalSession = {
      ...makeCurrentSession({
        principles: [...principles],
        findingsHash,
        sessionQuestions,
      }),
      version: '1.1' as const,
    };
    delete (transitionalSession as unknown as Record<string, unknown>).questionSetHash;

    const prepared = prepareQuestionnaireSessionForResume({
      session: transitionalSession,
      findings: [],
      expectedPrinciples: [...principles],
      expectedQuestions: sessionQuestions,
    });

    expect(prepared.didUpgrade).toBe(true);
    expect(prepared.session.version).toBe('1.2');
    expect(prepared.session.questionSetHash).toBeTruthy();
  });

  it('fails closed for non-canonical 1.1 sessions', () => {
    const principles = ['APP_1'] as const;
    const transitionalSession = {
      ...makeCurrentSession({
        principles: [...principles],
        sessionQuestions: buildFrozenSessionQuestions([...principles]).filter((question) => question.id !== 'Q-APP1-002'),
      }),
      version: '1.1' as const,
    };
    delete (transitionalSession as unknown as Record<string, unknown>).questionSetHash;

    expect(() => prepareQuestionnaireSessionForResume({
      session: transitionalSession,
      findings: [],
      expectedPrinciples: [...principles],
      expectedQuestions: buildFrozenSessionQuestions([...principles]),
    })).toThrow(/integrity check failed/i);
  });

  it('upgrades legacy 1.0 sessions once and freezes the legacy question set', () => {
    const legacySession: LegacyQuestionnaireSession = {
      id: 'legacy-session',
      version: '1.0',
      status: 'in_progress',
      target: {
        kind: 'path',
        name: 'Legacy App',
        path: '/tmp/legacy-app',
      },
      startedAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      strictMode: false,
      scanSnapshotPath: '/tmp/legacy-app/scan-results.json',
      findingsHash: buildFindingsHash([]),
      answers: [
        makeResponse('Q-APP5-001', true),
      ],
      principleResults: aggregatePrincipleResults(['APP_5'], [], LEGACY_QUESTION_BANK_V1),
      currentQuestionId: 'Q-APP5-002',
    };

    const prepared = prepareQuestionnaireSessionForResume({
      session: legacySession,
      findings: [],
      expectedPrinciples: ['APP_5'],
      expectedQuestions: buildFrozenSessionQuestions(['APP_5']),
    });
    const upgraded = prepared.session;

    expect(prepared.didUpgrade).toBe(true);
    expect(upgraded.version).toBe('1.2');
    expect(upgraded.questionnaireVersion).toBe(LEGACY_QUESTIONNAIRE_VERSION);
    expect(upgraded.principles).toEqual(['APP_5']);
    expect(upgraded.sessionQuestions.map((question) => question.id)).toEqual([
      'Q-APP5-001',
      'Q-APP5-002',
    ]);
    expect(upgraded.sessionQuestions.some((question) => question.id === 'Q-APP5-003')).toBe(false);
    expect(upgraded.questionSetHash).toBeTruthy();
  });
});
