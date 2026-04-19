import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import type { Question, QuestionnaireResponse, QuestionnaireSession } from '../schema/index.js';
import {
  aggregatePrincipleResults,
  buildFindingsHash,
  buildSessionPaths,
  createQuestionnaireSession,
  evaluateResponse,
  getApplicableQuestionsForPrinciple,
  loadQuestionnaireSession,
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

describe('questionnaire flow', () => {
  it('only activates APP 8 follow-up questions when overseas disclosure is confirmed', () => {
    const withoutDisclosure = getApplicableQuestionsForPrinciple('APP_8', []);
    expect(withoutDisclosure.map((question) => question.id)).toEqual(['Q-APP8-001']);

    const withDisclosure = getApplicableQuestionsForPrinciple('APP_8', [
      makeResponse('Q-APP8-001', true),
    ]);
    expect(withDisclosure.map((question) => question.id)).toEqual([
      'Q-APP8-001',
      'Q-APP8-002',
      'Q-APP8-003',
    ]);

    const withNegativeDisclosure = getApplicableQuestionsForPrinciple('APP_8', [
      makeResponse('Q-APP8-001', false),
    ]);
    expect(withNegativeDisclosure.map((question) => question.id)).toEqual(['Q-APP8-001']);
  });
});

describe('questionnaire evaluator', () => {
  it('marks fully answered required questions as pass', () => {
    const result = aggregatePrincipleResults(['APP_1'], [
      makeResponse('Q-APP1-001', true),
      makeResponse('Q-APP1-002', true),
    ])[0];

    expect(result).toMatchObject({
      principle: 'APP_1',
      status: 'pass',
    });
  });

  it('marks a principle as fail when any required answer fails', () => {
    const result = aggregatePrincipleResults(['APP_1'], [
      makeResponse('Q-APP1-001', true),
      makeResponse('Q-APP1-002', false),
    ])[0];

    expect(result).toMatchObject({
      principle: 'APP_1',
      status: 'fail',
    });
  });

  it('keeps a principle unknown when required answers are missing', () => {
    const result = aggregatePrincipleResults(['APP_1'], [
      makeResponse('Q-APP1-001', true),
    ])[0];

    expect(result).toMatchObject({
      principle: 'APP_1',
      status: 'unknown',
    });
  });

  it('keeps free-text answers unresolved and applies a modest evidence confidence boost to binary answers', () => {
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
    };
    const binaryResponse = evaluateResponse(binaryQuestion, {
      ...makeResponse('Q-YESNO-001', true),
      note: 'Published on website',
      evidenceRefs: ['docs/privacy-policy.md'],
    });

    expect(binaryResponse.status).toBe('pass');
    expect(binaryResponse.confidence).toBeGreaterThan(0.8);
  });
});

describe('questionnaire session persistence', () => {
  it('round-trips session state through session.json', async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-questionnaire-'));
    tempDirs.push(tempDir);

    const paths = buildSessionPaths(tempDir, 'Example App', 'session-123');
    await fs.mkdir(paths.directory, { recursive: true });

    const principleResults = aggregatePrincipleResults(['APP_1'], []);
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
      principleResults,
      currentQuestionId: 'Q-APP1-001',
    });

    await saveQuestionnaireSession(session, paths.sessionPath);
    const loaded = await loadQuestionnaireSession(paths.sessionPath);

    expect(loaded).toEqual<QuestionnaireSession>({
      ...session,
      updatedAt: loaded.updatedAt,
    });
    expect(loaded.currentQuestionId).toBe('Q-APP1-001');
    expect(loaded.target.path).toBe('/tmp/example-app');
  });
});
