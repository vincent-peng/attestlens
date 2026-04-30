import {
  APPInfo,
  type APPPrinciple,
  type AssessmentMode,
  type Jurisdiction,
  type Question,
  type QuestionnaireResponse,
} from '../schema/index.js';
import { CCPA_QUESTION_BANK } from './ccpa-questions.js';
import { QUESTION_BANK } from './questions.js';

const DEFAULT_ASSESSMENT_MODE: AssessmentMode = 'operator_attested';

export function getQuestionById(questionId: string, questions: Question[] = QUESTION_BANK): Question | undefined {
  return questions.find((question) => question.id === questionId);
}

export function getQuestionBankForJurisdiction(jurisdiction: Jurisdiction = 'au-privacy-act'): Question[] {
  if (jurisdiction === 'us-ccpa') {
    return CCPA_QUESTION_BANK as unknown as Question[];
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
  principle: APPPrinciple,
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

export function getQuestionPrincipleOrder(principles: APPPrinciple[]): APPPrinciple[] {
  const orderedPrinciples = Object.keys(APPInfo) as APPPrinciple[];
  return orderedPrinciples.filter((principle) => principles.includes(principle));
}

export function getNextQuestion(
  principles: APPPrinciple[],
  responses: QuestionnaireResponse[],
  questions: Question[] = QUESTION_BANK,
  assessmentMode: AssessmentMode = DEFAULT_ASSESSMENT_MODE,
): Question | undefined {
  const responsesByQuestionId = new Set(responses.map((response) => response.questionId));
  const principleOrder = getQuestionPrincipleOrder(principles);
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
