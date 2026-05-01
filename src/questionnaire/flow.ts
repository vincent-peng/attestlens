import {
  type AssessmentMode,
  type Jurisdiction,
  type Question,
  type QuestionnaireResponse,
  type RegulationPrinciple,
} from '../schema/index.js';
import { getRegistry } from '../jurisdiction/registry.js';
import { CCPA_QUESTION_BANK } from './ccpa-questions.js';
import { GDPR_QUESTION_BANK } from './gdpr-questions.js';
import { QUESTION_BANK } from './questions.js';
import { SG_PDPA_QUESTION_BANK } from './sg-pdpa-questions.js';

const DEFAULT_ASSESSMENT_MODE: AssessmentMode = 'operator_attested';

export function getQuestionById(questionId: string, questions: Question[] = QUESTION_BANK): Question | undefined {
  return questions.find((question) => question.id === questionId);
}

export function getQuestionBankForJurisdiction(jurisdiction: Jurisdiction = 'au-privacy-act'): Question[] {
  const questionBank = jurisdiction === 'us-ccpa'
    ? CCPA_QUESTION_BANK
    : jurisdiction === 'eu-gdpr'
      ? GDPR_QUESTION_BANK
      : jurisdiction === 'sg-pdpa'
        ? SG_PDPA_QUESTION_BANK
        : QUESTION_BANK;
  const principleRank = new Map(
    getQuestionPrincipleOrder(
      questionBank.map((question) => question.regulationPrinciple),
      jurisdiction,
    ).map((principle, index) => [principle, index]),
  );
  return [...questionBank].sort((left, right) => (
    (principleRank.get(left.regulationPrinciple) ?? Number.MAX_SAFE_INTEGER)
    - (principleRank.get(right.regulationPrinciple) ?? Number.MAX_SAFE_INTEGER)
  ));
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
    questions.filter((question) => question.regulationPrinciple === principle),
    responses,
    assessmentMode,
  );
}

export function getQuestionPrincipleOrder(
  principles: RegulationPrinciple[],
  jurisdiction: Jurisdiction = inferJurisdictionForPrinciples(principles),
): RegulationPrinciple[] {
  const orderedPrinciples = getRegistry(jurisdiction).order;
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
  const scopedQuestions = questions.filter((question) => principles.includes(question.regulationPrinciple));

  for (const principle of principleOrder) {
    const principleQuestions = getApplicableQuestions(
      scopedQuestions.filter((question) => question.regulationPrinciple === principle),
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
  if (principles.some((principle) => principle.startsWith('SGPDPA_'))) {
    return 'sg-pdpa';
  }
  return 'au-privacy-act';
}
