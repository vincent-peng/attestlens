import {
  APPInfo,
  type AssessmentMode,
  type Jurisdiction,
  type Question,
  type QuestionnaireResponse,
  type RegulationPrinciple,
} from '../schema/index.js';
import { CCPAPrincipleInfo } from '../scanner/rules/ccpa-principles.js';
import { GDPRPrincipleInfo } from '../scanner/rules/gdpr-principles.js';
import { CCPA_QUESTION_BANK } from './ccpa-questions.js';
import { GDPR_QUESTION_BANK } from './gdpr-questions.js';
import { QUESTION_BANK } from './questions.js';

const DEFAULT_ASSESSMENT_MODE: AssessmentMode = 'operator_attested';

export function getQuestionById(questionId: string, questions: Question[] = QUESTION_BANK): Question | undefined {
  return questions.find((question) => question.id === questionId);
}

export function getQuestionBankForJurisdiction(jurisdiction: Jurisdiction = 'au-privacy-act'): Question[] {
  if (jurisdiction === 'us-ccpa') {
    const principleRank = new Map(
      getQuestionPrincipleOrder(Object.keys(CCPAPrincipleInfo), 'us-ccpa')
        .map((principle, index) => [principle, index]),
    );
    return [...CCPA_QUESTION_BANK].sort((left, right) => (
      (principleRank.get(left.appPrinciple) ?? Number.MAX_SAFE_INTEGER)
      - (principleRank.get(right.appPrinciple) ?? Number.MAX_SAFE_INTEGER)
    ));
  }

  if (jurisdiction === 'eu-gdpr') {
    const principleRank = new Map(
      getQuestionPrincipleOrder(Object.keys(GDPRPrincipleInfo), 'eu-gdpr')
        .map((principle, index) => [principle, index]),
    );
    return [...GDPR_QUESTION_BANK].sort((left, right) => (
      (principleRank.get(left.appPrinciple) ?? Number.MAX_SAFE_INTEGER)
      - (principleRank.get(right.appPrinciple) ?? Number.MAX_SAFE_INTEGER)
    ));
  }

  return QUESTION_BANK;
}

function normalizeAnswers(value: QuestionnaireResponse['answer']): Array<boolean | string> {
  return Array.isArray(value) ? value : [value];
}

export function isQuestionApplicable(
  question: Question,
  responses: QuestionnaireResponse[],
  assessmentMode: AssessmentMode = DEFAULT_ASSESSMENT_MODE,
): boolean {
  if (question.assessmentModes && !question.assessmentModes.includes(assessmentMode)) {
    return false;
  }

  if (!question.dependsOn) {
    return true;
  }

  const dependencyResponse = responses.find((response) => response.questionId === question.dependsOn?.questionId);
  if (!dependencyResponse) {
    return false;
  }

  const responseAnswers = normalizeAnswers(dependencyResponse.answer);
  return question.dependsOn.answers.some((expectedAnswer) => responseAnswers.includes(expectedAnswer));
}

export function getApplicableQuestions(
  questions: Question[],
  responses: QuestionnaireResponse[],
  assessmentMode: AssessmentMode = DEFAULT_ASSESSMENT_MODE,
): Question[] {
  return questions.filter((question) => isQuestionApplicable(question, responses, assessmentMode));
}

export function getApplicableQuestionsForPrinciple(
  principle: RegulationPrinciple,
  responses: QuestionnaireResponse[],
  questions: Question[] = QUESTION_BANK,
  assessmentMode: AssessmentMode = DEFAULT_ASSESSMENT_MODE,
): Question[] {
  return getApplicableQuestions(
    questions.filter((question) => question.appPrinciple === principle),
    responses,
    assessmentMode,
  );
}

export function getQuestionPrincipleOrder(
  principles: RegulationPrinciple[],
  jurisdiction: Jurisdiction = inferJurisdictionForPrinciples(principles),
): RegulationPrinciple[] {
  const orderedPrinciples = jurisdiction === 'us-ccpa'
    ? Object.keys(CCPAPrincipleInfo)
    : jurisdiction === 'eu-gdpr'
      ? Object.keys(GDPRPrincipleInfo)
      : Object.keys(APPInfo);
  const requested = new Set(principles);
  return orderedPrinciples.filter((principle) => requested.has(principle));
}

export function getNextQuestion(
  principles: RegulationPrinciple[],
  responses: QuestionnaireResponse[],
  questions: Question[] = QUESTION_BANK,
  assessmentMode: AssessmentMode = DEFAULT_ASSESSMENT_MODE,
  jurisdiction: Jurisdiction = inferJurisdictionForPrinciples(principles),
): Question | undefined {
  const responsesByQuestionId = new Set(responses.map((response) => response.questionId));
  const principleOrder = getQuestionPrincipleOrder(principles, jurisdiction);
  const scopedQuestions = questions.filter((question) => principles.includes(question.appPrinciple));

  for (const principle of principleOrder) {
    const principleQuestions = getApplicableQuestions(
      scopedQuestions.filter((question) => question.appPrinciple === principle),
      responses,
      assessmentMode,
    );
    const orderedQuestions = [
      ...principleQuestions.filter((question) => question.required),
      ...principleQuestions.filter((question) => !question.required),
    ];

    const nextQuestion = orderedQuestions.find((question) => !responsesByQuestionId.has(question.id));
    if (nextQuestion) {
      return nextQuestion;
    }
  }

  return undefined;
}

function inferJurisdictionForPrinciples(principles: RegulationPrinciple[]): Jurisdiction {
  if (principles.some((principle) => principle.startsWith('CCPA_'))) {
    return 'us-ccpa';
  }
  if (principles.some((principle) => principle.startsWith('GDPR_'))) {
    return 'eu-gdpr';
  }
  return 'au-privacy-act';
}
