import { APPInfo, type APPPrinciple, type Question, type QuestionnaireResponse } from '../schema/index.js';
import { QUESTION_BANK, getQuestionsForUnknownControls } from './questions.js';

export function getQuestionById(questionId: string, questions: Question[] = QUESTION_BANK): Question | undefined {
  return questions.find((question) => question.id === questionId);
}

function normalizeAnswers(value: QuestionnaireResponse['answer']): Array<boolean | string> {
  return Array.isArray(value) ? value : [value];
}

export function isQuestionApplicable(
  question: Question,
  responses: QuestionnaireResponse[],
): boolean {
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
): Question[] {
  return questions.filter((question) => isQuestionApplicable(question, responses));
}

export function getApplicableQuestionsForPrinciple(
  principle: APPPrinciple,
  responses: QuestionnaireResponse[],
  questions: Question[] = QUESTION_BANK,
): Question[] {
  return getApplicableQuestions(
    questions.filter((question) => question.appPrinciple === principle),
    responses,
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
): Question | undefined {
  const responsesByQuestionId = new Set(responses.map((response) => response.questionId));
  const principleOrder = getQuestionPrincipleOrder(principles);
  const scopedQuestionIds = new Set(getQuestionsForUnknownControls(principles).map((question) => question.id));
  const scopedQuestions = questions.filter((question) => scopedQuestionIds.has(question.id));

  for (const principle of principleOrder) {
    const principleQuestions = getApplicableQuestions(
      scopedQuestions.filter((question) => question.appPrinciple === principle),
      responses,
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
