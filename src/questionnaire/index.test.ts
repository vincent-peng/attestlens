import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import type {
  AssessmentMode,
  AttestLensFinding,
  LegacyQuestionnaireSession,
  Question,
  QuestionnaireResponse,
  QuestionnaireSession,
} from '../schema/index.js';
import {
  CCPA_QUESTION_BANK,
  GDPR_QUESTION_BANK,
  SG_PDPA_QUESTION_BANK,
  LEGACY_QUESTION_BANK_V1,
  LEGACY_QUESTIONNAIRE_VERSION,
  PRE_REMEDIATION_QUESTION_BANK_V2,
  PRE_REMEDIATION_QUESTIONNAIRE_VERSION,
  QUESTION_BANK,
  QUESTIONNAIRE_VERSION,
  SESSION_INTEGRITY_FAILURE,
  UPGRADE_ASSESSMENT_MODE_REQUIRED,
  aggregatePrincipleResults,
  buildAttestationScanSnapshot,
  buildFindingsHash,
  buildFrozenSessionQuestions,
  buildQuestionSetHash,
  buildSessionPaths,
  createQuestionnaireSession,
  deriveQuestionnairePrinciples,
  evaluateResponse,
  getApplicableQuestionsForPrinciple,
  getQuestionBankForJurisdiction,
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
  const assessmentMode = overrides.assessmentMode || 'operator_attested';

  return {
    id: overrides.id || 'session-001',
    version: '1.3',
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
      assessmentMode,
    }),
    assessmentMode,
    answers: overrides.answers || [],
    principleResults: overrides.principleResults || aggregatePrincipleResults(principles, [], sessionQuestions, assessmentMode),
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

  it('orders the CCPA question bank by CCPA principle order', () => {
    expect(getQuestionBankForJurisdiction('us-ccpa').map((question) => question.id)).toEqual(
      CCPA_QUESTION_BANK.map((question) => question.id),
    );
    expect(getQuestionBankForJurisdiction('us-ccpa')[0]?.appPrinciple).toBe('CCPA_100');
  });

  it('orders the GDPR question bank by GDPR principle order', () => {
    expect(getQuestionBankForJurisdiction('eu-gdpr').map((question) => question.id)).toEqual(
      GDPR_QUESTION_BANK.map((question) => question.id),
    );
    expect(getQuestionBankForJurisdiction('eu-gdpr')[0]?.appPrinciple).toBe('GDPR_Art3');
  });

  it('orders the SG PDPA question bank by SG PDPA principle order', () => {
    expect(getQuestionBankForJurisdiction('sg-pdpa').map((question) => question.id)).toEqual(
      SG_PDPA_QUESTION_BANK.map((question) => question.id),
    );
    expect(getQuestionBankForJurisdiction('sg-pdpa')[0]?.appPrinciple).toBe('SGPDPA_11');
  });

  it('evaluates CCPA no-discrimination as a control where yes fails and no passes', () => {
    const question = CCPA_QUESTION_BANK.find((candidate) => candidate.id === 'Q-CCPA125-001')!;

    expect(evaluateResponse(question, makeResponse(question.id, true))).toEqual(expect.objectContaining({
      status: 'fail',
    }));
    expect(evaluateResponse(question, makeResponse(question.id, false))).toEqual(expect.objectContaining({
      status: 'pass',
    }));
  });

  it('evaluates CCPA applicability threshold answers as gate outcomes', () => {
    const question = CCPA_QUESTION_BANK.find((candidate) => candidate.id === 'Q-CCPA145-001')!;

    expect(evaluateResponse(question, makeResponse(question.id, false))).toEqual(expect.objectContaining({
      status: 'pass',
      rationale: expect.stringContaining('Applicability gate satisfied'),
    }));
    expect(evaluateResponse(question, makeResponse(question.id, true))).toEqual(expect.objectContaining({
      status: 'pass',
      rationale: expect.stringContaining('Applicability confirmed'),
    }));
  });

  it('evaluates GDPR applicability gates as pass-on-no gates', () => {
    for (const questionId of [
      'Q-GDPR-Art3-001',
      'Q-GDPR-Art9-001',
      'Q-GDPR-Art22-001',
      'Q-GDPR-Art44-001',
    ]) {
      const question = GDPR_QUESTION_BANK.find((candidate) => candidate.id === questionId)!;

      expect(evaluateResponse(question, makeResponse(question.id, false))).toEqual(expect.objectContaining({
        status: 'pass',
        rationale: expect.stringContaining('Applicability gate satisfied'),
      }));
      expect(evaluateResponse(question, makeResponse(question.id, true))).toEqual(expect.objectContaining({
        status: 'pass',
        rationale: expect.stringContaining('Applicability confirmed'),
      }));
    }
  });

  it('evaluates GDPR control answers as pass/fail paths', () => {
    const question = GDPR_QUESTION_BANK.find((candidate) => candidate.id === 'Q-GDPR-Art32-001')!;

    expect(evaluateResponse(question, makeResponse(question.id, true))).toEqual(expect.objectContaining({
      status: 'pass',
    }));
    expect(evaluateResponse(question, makeResponse(question.id, false))).toEqual(expect.objectContaining({
      status: 'fail',
    }));
  });

  it('gates GDPR special category and transfer follow-ups behind applicability answers', () => {
    expect(getApplicableQuestionsForPrinciple('GDPR_Art9', [], GDPR_QUESTION_BANK).map((question) => question.id)).toEqual([
      'Q-GDPR-Art9-001',
    ]);
    expect(getApplicableQuestionsForPrinciple('GDPR_Art9', [
      makeResponse('Q-GDPR-Art9-001', true),
    ], GDPR_QUESTION_BANK).map((question) => question.id)).toEqual([
      'Q-GDPR-Art9-001',
      'Q-GDPR-Art9-002',
    ]);
    expect(getApplicableQuestionsForPrinciple('GDPR_Art44', [
      makeResponse('Q-GDPR-Art44-001', false),
    ], GDPR_QUESTION_BANK).map((question) => question.id)).toEqual([
      'Q-GDPR-Art44-001',
    ]);
  });

  it('routes advisory GDPR findings to the questionnaire principles that resolve them', () => {
    const cases = [
      { ruleId: 'GDPR-CONSENT-001', principle: 'GDPR_Art6', obligation: 'Lawful basis' },
      { ruleId: 'GDPR-TRANSFER-001', principle: 'GDPR_Art44', obligation: 'International transfers' },
      { ruleId: 'GDPR-DPIA-001', principle: 'GDPR_Art35', obligation: 'DPIA' },
      { ruleId: 'GDPR-ART22-001', principle: 'GDPR_Art22', obligation: 'Automated decisions' },
    ] as const;

    for (const testCase of cases) {
      const finding: AttestLensFinding = {
        id: `F-${testCase.ruleId}`,
        source: 'guardvibe',
        sourceRule: testCase.ruleId,
        severity: 'medium',
        category: 'gdpr-advisory',
        title: testCase.ruleId,
        description: 'Advisory GDPR scanner finding',
        file: 'src/app.ts',
        line: 1,
        appMappings: [],
        regulationMappings: [{
          jurisdiction: 'eu-gdpr',
          principle: testCase.principle,
          obligation: testCase.obligation,
          status: 'unknown',
          confidence: 0.5,
        }],
        evidence: {
          timestamp: new Date().toISOString(),
          scannerVersion: 'test',
          rawOutput: {},
        },
      };

      expect(deriveQuestionnairePrinciples([finding], 'eu-gdpr')).toContain(testCase.principle);
    }
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
      makeResponse('Q-APP5-000', true),
      makeResponse('Q-APP5-003', false),
    ]);
    expect(directOnly.map((question) => question.id)).toEqual([
      'Q-APP5-000',
      'Q-APP5-001',
      'Q-APP5-003',
    ]);

    const indirectCollection = getApplicableQuestionsForPrinciple('APP_5', [
      makeResponse('Q-APP5-000', true),
      makeResponse('Q-APP5-003', true),
    ]);
    expect(indirectCollection.map((question) => question.id)).toEqual([
      'Q-APP5-000',
      'Q-APP5-001',
      'Q-APP5-003',
      'Q-APP5-002',
    ]);
  });

  it('gates APP 3 direct collection controls behind the reviewed-surface collection gate', () => {
    const noDirectCollection = getApplicableQuestionsForPrinciple('APP_3', [
      makeResponse('Q-APP3-000', false),
    ]);
    expect(noDirectCollection.map((question) => question.id)).toEqual(['Q-APP3-000']);

    const directCollection = getApplicableQuestionsForPrinciple('APP_3', [
      makeResponse('Q-APP3-000', true),
    ]);
    expect(directCollection.map((question) => question.id)).toEqual([
      'Q-APP3-000',
      'Q-APP3-001',
      'Q-APP3-002',
      'Q-APP3-003',
      'Q-APP3-004',
    ]);
  });

  it('removes operator-attested governance questions from artifact-only runs', () => {
    const artifactOnlyQuestions = getApplicableQuestionsForPrinciple('APP_6', [], QUESTION_BANK, 'artifact_only');
    expect(artifactOnlyQuestions).toEqual([]);

    const operatorQuestions = getApplicableQuestionsForPrinciple('APP_6', [], QUESTION_BANK, 'operator_attested');
    expect(operatorQuestions.map((question) => question.id)).toEqual(['Q-APP6-001']);
  });

  it('gates APP 2 follow-up questions behind the anonymity exception path', () => {
    const anonymousFlow = getApplicableQuestionsForPrinciple('APP_2', [
      makeResponse('Q-APP2-001', true),
    ]);
    expect(anonymousFlow.map((question) => question.id)).toEqual(['Q-APP2-001']);

    const identifiedOperatorFlow = getApplicableQuestionsForPrinciple('APP_2', [
      makeResponse('Q-APP2-001', false),
    ]);
    expect(identifiedOperatorFlow.map((question) => question.id)).toEqual([
      'Q-APP2-001',
      'Q-APP2-002',
    ]);

    const identifiedArtifactFlow = getApplicableQuestionsForPrinciple('APP_2', [
      makeResponse('Q-APP2-001', false),
    ], QUESTION_BANK, 'artifact_only');
    expect(identifiedArtifactFlow.map((question) => question.id)).toEqual([
      'Q-APP2-001',
      'Q-APP2-003',
    ]);
  });
});

describe('attestation scan snapshots', () => {
  it('strips internal cache paths from rule freshness metadata', () => {
    const snapshot = buildAttestationScanSnapshot({
      target: {
        kind: 'path',
        name: 'Example App',
        path: '/tmp/example-app',
      },
      findings: [],
      ruleFreshness: {
        version: '2026.04.24',
        generated: '2026-04-24T00:00:00.000Z',
        loadedAt: '2026-04-24T01:00:00.000Z',
        source: 'cache',
        cachePath: '/Users/alice/.attestlens/rules/latest.json',
        ruleCount: 42,
        ageDays: 0,
        stale: false,
      } as any,
    });

    expect(snapshot.ruleFreshness).toEqual({
      version: '2026.04.24',
      generated: '2026-04-24T00:00:00.000Z',
      loadedAt: '2026-04-24T01:00:00.000Z',
      source: 'cache',
      ruleCount: 42,
      ageDays: 0,
      stale: false,
    });
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
      regulationPrinciple: 'APP_1',
      jurisdiction: 'au-privacy-act',
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
      regulationPrinciple: 'APP_1',
      jurisdiction: 'au-privacy-act',
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

  it('keeps governance-heavy principles unknown in artifact-only mode', () => {
    const result = aggregatePrincipleResults(['APP_6', 'NDB'], [], QUESTION_BANK, 'artifact_only');

    expect(result).toEqual([
      expect.objectContaining({
        principle: 'APP_6',
        status: 'unknown',
      }),
      expect.objectContaining({
        principle: 'NDB',
        status: 'unknown',
      }),
    ]);
  });

  it('keeps operator-attested governance-heavy principles answerable in operator mode', () => {
    const result = aggregatePrincipleResults(['APP_6'], [
      makeResponse('Q-APP6-001', true),
    ], QUESTION_BANK, 'operator_attested')[0];

    expect(result).toMatchObject({
      principle: 'APP_6',
      status: 'pass',
    });
  });

  it('passes APP 3 and APP 5 direct collection branches when the reviewed surface does not directly collect personal information', () => {
    const result = aggregatePrincipleResults(['APP_3', 'APP_5'], [
      makeResponse('Q-APP3-000', false),
      makeResponse('Q-APP5-000', false),
      makeResponse('Q-APP5-003', false),
    ])[0];

    expect(result).toMatchObject({
      principle: 'APP_3',
      status: 'pass',
    });

    const app5Result = aggregatePrincipleResults(['APP_5'], [
      makeResponse('Q-APP5-000', false),
      makeResponse('Q-APP5-003', false),
    ])[0];
    expect(app5Result).toMatchObject({
      principle: 'APP_5',
      status: 'pass',
    });
  });

  it('keeps APP 2 unknown in artifact-only mode when the exception basis is not established', () => {
    const result = aggregatePrincipleResults(['APP_2'], [
      makeResponse('Q-APP2-001', false),
      makeResponse('Q-APP2-003', 'na'),
    ], QUESTION_BANK, 'artifact_only')[0];

    expect(result).toMatchObject({
      principle: 'APP_2',
      status: 'unknown',
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
  it('round-trips a 1.3 session through session.json with frozen question metadata, assessment mode, and integrity hash', async () => {
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
      assessmentMode: 'artifact_only',
      currentQuestionId: 'Q-APP1-001',
    });

    await saveQuestionnaireSession(session, paths.sessionPath);
    const loaded = await loadQuestionnaireSession(paths.sessionPath);

    expect(loaded.version).toBe('1.3');
    if (loaded.version !== '1.3') {
      throw new Error('Expected a 1.3 questionnaire session');
    }

    expect(loaded).toEqual<QuestionnaireSession>({
      ...session,
      updatedAt: loaded.updatedAt,
    });
    expect(loaded.questionnaireVersion).toBe(QUESTIONNAIRE_VERSION);
    expect(loaded.principles).toEqual(['APP_1']);
    expect(loaded.assessmentMode).toBe('artifact_only');
    expect(loaded.sessionQuestions.map((question) => question.id)).toEqual([
      'Q-APP1-001',
      'Q-APP1-002',
      'Q-APP1-003',
    ]);
    expect(loaded.questionSetHash).toBeTruthy();
  });

  it('validates a canonical 1.3 session against the frozen snapshot', () => {
    const session = makeCurrentSession({
      principles: ['APP_1'],
      currentQuestionId: 'Q-APP1-001',
      assessmentMode: 'codebase_only',
    });

    const prepared = prepareQuestionnaireSessionForResume({
      session,
      findings: [],
      expectedPrinciples: ['APP_1'],
      expectedQuestions: buildFrozenSessionQuestions(['APP_1']),
    });

    expect(prepared.didUpgrade).toBe(false);
    expect(prepared.session.version).toBe('1.3');
    expect(prepared.session.assessmentMode).toBe('codebase_only');
  });

  it('rejects tampered 1.3 sessions when frozen questions no longer match the canonical set', () => {
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

  it('rejects tampered 1.3 sessions when the principles no longer match the frozen snapshot', () => {
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

  it('rejects 1.3 resumes when the frozen scan findings hash no longer matches', () => {
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
      regulationMappings: [],
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

  it('rejects tampered 1.3 sessions when the frozen assessment mode no longer matches the integrity hash', () => {
    const session = makeCurrentSession({
      assessmentMode: 'artifact_only',
    });
    const tamperedSession = {
      ...session,
      assessmentMode: 'operator_attested' as AssessmentMode,
    };

    expect(() => prepareQuestionnaireSessionForResume({
      session: tamperedSession,
      findings: [],
      expectedPrinciples: session.principles,
      expectedQuestions: session.sessionQuestions,
    })).toThrow(/integrity check failed/i);
  });

  it('requires an explicit assessment basis before upgrading pre-1.3 sessions', () => {
    const principles = ['APP_6'] as const;
    const sessionQuestions = buildFrozenSessionQuestions([...principles], PRE_REMEDIATION_QUESTION_BANK_V2);
    const findingsHash = buildFindingsHash([]);
    const frozenSession = {
      ...makeCurrentSession({
        principles: [...principles],
        findingsHash,
        questionnaireVersion: PRE_REMEDIATION_QUESTIONNAIRE_VERSION,
        sessionQuestions,
      }),
      version: '1.2' as const,
      questionSetHash: buildQuestionSetHash({
        questionnaireVersion: PRE_REMEDIATION_QUESTIONNAIRE_VERSION,
        findingsHash,
        principles: [...principles],
        sessionQuestions,
      }),
    };
    delete (frozenSession as unknown as Record<string, unknown>).assessmentMode;

    expect(() => prepareQuestionnaireSessionForResume({
      session: frozenSession,
      findings: [],
      expectedPrinciples: [...principles],
      expectedQuestions: buildFrozenSessionQuestions([...principles]),
    })).toThrow(UPGRADE_ASSESSMENT_MODE_REQUIRED);
  });

  it('upgrades known pre-remediation 1.2 sessions to 1.3 with an explicit assessment basis', () => {
    const principles = ['APP_6'] as const;
    const sessionQuestions = buildFrozenSessionQuestions([...principles], PRE_REMEDIATION_QUESTION_BANK_V2);
    const findingsHash = buildFindingsHash([]);
    const frozenSession = {
      ...makeCurrentSession({
        principles: [...principles],
        findingsHash,
        questionnaireVersion: PRE_REMEDIATION_QUESTIONNAIRE_VERSION,
        sessionQuestions,
      }),
      version: '1.2' as const,
      questionSetHash: buildQuestionSetHash({
        questionnaireVersion: PRE_REMEDIATION_QUESTIONNAIRE_VERSION,
        findingsHash,
        principles: [...principles],
        sessionQuestions,
      }),
    };
    delete (frozenSession as unknown as Record<string, unknown>).assessmentMode;

    const prepared = prepareQuestionnaireSessionForResume({
      session: frozenSession,
      findings: [],
      expectedPrinciples: [...principles],
      expectedQuestions: buildFrozenSessionQuestions([...principles]),
      upgradeAssessmentMode: 'artifact_only',
    });

    expect(prepared.didUpgrade).toBe(true);
    expect(prepared.session.version).toBe('1.3');
    expect(prepared.session.questionnaireVersion).toBe(QUESTIONNAIRE_VERSION);
    expect(prepared.session.assessmentMode).toBe('artifact_only');
    expect(prepared.session.sessionQuestions).toEqual(buildFrozenSessionQuestions([...principles]));
    expect(prepared.session.questionSetHash).toBeTruthy();
  });

  it('fails closed for unknown 1.2 questionnaire versions', () => {
    const principles = ['APP_1'] as const;
    const sessionQuestions = buildFrozenSessionQuestions([...principles]);
    const findingsHash = buildFindingsHash([]);
    const frozenSession = {
      ...makeCurrentSession({
        principles: [...principles],
        findingsHash,
        questionnaireVersion: 'unknown-v1',
        sessionQuestions,
      }),
      version: '1.2' as const,
      questionSetHash: buildQuestionSetHash({
        questionnaireVersion: 'unknown-v1',
        findingsHash,
        principles: [...principles],
        sessionQuestions,
      }),
    };
    delete (frozenSession as unknown as Record<string, unknown>).assessmentMode;

    expect(() => prepareQuestionnaireSessionForResume({
      session: frozenSession,
      findings: [],
      expectedPrinciples: [...principles],
      expectedQuestions: buildFrozenSessionQuestions([...principles]),
      upgradeAssessmentMode: 'operator_attested',
    })).toThrow(SESSION_INTEGRITY_FAILURE);
  });

  it('upgrades canonical 1.1 sessions to 1.3 only when they exactly match the canonical frozen set', () => {
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
      upgradeAssessmentMode: 'operator_attested',
    });

    expect(prepared.didUpgrade).toBe(true);
    expect(prepared.session.version).toBe('1.3');
    expect(prepared.session.assessmentMode).toBe('operator_attested');
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
      upgradeAssessmentMode: 'operator_attested',
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
      upgradeAssessmentMode: 'operator_attested',
    });
    const upgraded = prepared.session;

    expect(prepared.didUpgrade).toBe(true);
    expect(upgraded.version).toBe('1.3');
    expect(upgraded.questionnaireVersion).toBe(LEGACY_QUESTIONNAIRE_VERSION);
    expect(upgraded.principles).toEqual(['APP_5']);
    expect(upgraded.assessmentMode).toBe('operator_attested');
    expect(upgraded.sessionQuestions.map((question) => question.id)).toEqual([
      'Q-APP5-001',
      'Q-APP5-002',
    ]);
    expect(upgraded.sessionQuestions.some((question) => question.id === 'Q-APP5-003')).toBe(false);
    expect(upgraded.questionSetHash).toBeTruthy();
  });
});
