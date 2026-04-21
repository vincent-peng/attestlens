import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import type { LegacyQuestionnaireSession, Question, QuestionnaireResponse, QuestionnaireSession } from '../schema/index.js';
import {
  LEGACY_QUESTION_BANK_V1,
  LEGACY_QUESTIONNAIRE_VERSION,
  QUESTION_BANK,
  QUESTIONNAIRE_VERSION,
  aggregatePrincipleResults,
  buildFindingsHash,
  buildFrozenSessionQuestions,
  buildSessionPaths,
  createQuestionnaireSession,
  evaluateResponse,
  getApplicableQuestionsForPrinciple,
  loadQuestionnaireSession,
  saveQuestionnaireSession,
  upgradeQuestionnaireSession,
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
});

describe('questionnaire session persistence', () => {
  it('round-trips a 1.1 session through session.json with frozen question metadata', async () => {
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

    expect(loaded.version).toBe('1.1');
    if (loaded.version !== '1.1') {
      throw new Error('Expected a 1.1 questionnaire session');
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
      findingsHash: 'legacy-hash',
      answers: [
        makeResponse('Q-APP5-001', true),
      ],
      principleResults: aggregatePrincipleResults(['APP_5'], [], LEGACY_QUESTION_BANK_V1),
      currentQuestionId: 'Q-APP5-002',
    };

    const upgraded = upgradeQuestionnaireSession(legacySession);

    expect(upgraded.version).toBe('1.1');
    expect(upgraded.questionnaireVersion).toBe(LEGACY_QUESTIONNAIRE_VERSION);
    expect(upgraded.principles).toEqual(['APP_5']);
    expect(upgraded.sessionQuestions.map((question) => question.id)).toEqual([
      'Q-APP5-001',
      'Q-APP5-002',
    ]);
    expect(upgraded.sessionQuestions.some((question) => question.id === 'Q-APP5-003')).toBe(false);
  });
});
