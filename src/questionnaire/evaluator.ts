import type {
  APPPrinciple,
  Question,
  QuestionnaireEvaluation,
  QuestionnairePrincipleResult,
  QuestionnaireResponse,
} from '../schema/index.js';
import { getApplicableQuestionsForPrinciple, getQuestionById } from './flow.js';
import { QUESTION_BANK } from './questions.js';

function withEvidenceConfidenceBoost(
  evaluation: QuestionnaireEvaluation,
  answer: QuestionnaireResponse,
): QuestionnaireEvaluation {
  const hasEvidence = Boolean(answer.note?.trim() || answer.evidenceRefs?.length);
  if (!hasEvidence) {
    return evaluation;
  }

  return {
    ...evaluation,
    confidence: Math.min(0.95, evaluation.confidence + 0.05),
  };
}

export function evaluateResponse(
  question: Question,
  answer: QuestionnaireResponse,
): QuestionnaireEvaluation {
  const { answer: value } = answer;

  switch (question.type) {
    case 'yes_no': {
      const evaluation = value === true || value === 'yes'
        ? {
            status: 'pass' as const,
            confidence: 0.80,
            rationale: `Affirmative response to: "${question.question}"`,
          }
        : {
            status: 'fail' as const,
            confidence: 0.85,
            rationale: `Negative response to: "${question.question}"`,
          };
      return withEvidenceConfidenceBoost(evaluation, answer);
    }

    case 'yes_no_na': {
      if (value === 'na' || value === 'N/A') {
        return withEvidenceConfidenceBoost({
          status: 'pass',
          confidence: 0.70,
          rationale: `Marked not applicable for: "${question.question}"`,
        }, answer);
      }

      const evaluation = value === true || value === 'yes'
        ? {
            status: 'pass' as const,
            confidence: 0.80,
            rationale: `Affirmative response to: "${question.question}"`,
          }
        : {
            status: 'fail' as const,
            confidence: 0.85,
            rationale: `Negative response to: "${question.question}"`,
          };
      return withEvidenceConfidenceBoost(evaluation, answer);
    }

    case 'multi_choice': {
      const choices = value as string[];
      if (choices.includes('None of the above')) {
        return withEvidenceConfidenceBoost({
          status: 'fail',
          confidence: 0.90,
          rationale: `No compliance steps selected for: "${question.question}"`,
        }, answer);
      }

      if (choices.length >= 2) {
        return withEvidenceConfidenceBoost({
          status: 'pass',
          confidence: 0.75,
          rationale: `${choices.length} compliance steps selected for: "${question.question}"`,
        }, answer);
      }

      if (choices.length === 1) {
        return withEvidenceConfidenceBoost({
          status: 'pass',
          confidence: 0.60,
          rationale: `Single compliance step selected for: "${question.question}"`,
        }, answer);
      }

      return {
        status: 'unknown',
        confidence: 0.30,
        rationale: `No response provided for: "${question.question}"`,
      };
    }

    case 'text':
      return {
        status: 'unknown',
        confidence: 0.20,
        rationale: `Free text response requires manual review for: "${question.question}"`,
      };

    default:
      return {
        status: 'unknown',
        confidence: 0.10,
        rationale: 'Unsupported question type',
      };
  }
}

export function evaluateStoredResponse(answer: QuestionnaireResponse): QuestionnaireResponse {
  if (answer.evaluation) {
    return answer;
  }

  const question = getQuestionById(answer.questionId);
  if (!question) {
    return answer;
  }

  return {
    ...answer,
    evaluation: evaluateResponse(question, answer),
  };
}

export function aggregatePrincipleResults(
  principles: APPPrinciple[],
  responses: QuestionnaireResponse[],
): QuestionnairePrincipleResult[] {
  const evaluatedResponses = responses.map(evaluateStoredResponse);

  return principles.map((principle) => {
    const applicableQuestions = getApplicableQuestionsForPrinciple(principle, evaluatedResponses, QUESTION_BANK);
    const answeredResponses = applicableQuestions
      .map((question) => evaluatedResponses.find((response) => response.questionId === question.id))
      .filter((response): response is QuestionnaireResponse => Boolean(response));
    const answeredQuestionIds = answeredResponses.map((response) => response.questionId);
    const requiredQuestions = applicableQuestions.filter((question) => question.required);
    const unansweredRequired = requiredQuestions.filter((question) => !answeredQuestionIds.includes(question.id));
    const failEvaluations = answeredResponses
      .map((response) => response.evaluation)
      .filter((evaluation): evaluation is QuestionnaireEvaluation => Boolean(evaluation))
      .filter((evaluation) => evaluation.status === 'fail');

    if (unansweredRequired.length > 0) {
      return {
        principle,
        status: 'unknown',
        confidence: 0.0,
        rationale: `Awaiting required questionnaire answers: ${unansweredRequired.map((question) => question.id).join(', ')}`,
        answeredQuestionIds,
      };
    }

    if (failEvaluations.length > 0) {
      const strongestFailure = failEvaluations.reduce((current, evaluation) => (
        evaluation.confidence > current.confidence ? evaluation : current
      ), failEvaluations[0]!);

      return {
        principle,
        status: 'fail',
        confidence: strongestFailure.confidence,
        rationale: strongestFailure.rationale,
        answeredQuestionIds,
      };
    }

    const requiredEvaluations = answeredResponses
      .filter((response) => requiredQuestions.some((question) => question.id === response.questionId))
      .map((response) => response.evaluation)
      .filter((evaluation): evaluation is QuestionnaireEvaluation => Boolean(evaluation));

    if (requiredEvaluations.length === 0) {
      return {
        principle,
        status: 'unknown',
        confidence: 0.0,
        rationale: 'No applicable questionnaire answers have been recorded yet.',
        answeredQuestionIds,
      };
    }

    const averageConfidence = requiredEvaluations.reduce((sum, evaluation) => sum + evaluation.confidence, 0) / requiredEvaluations.length;
    return {
      principle,
      status: 'pass',
      confidence: Math.round(averageConfidence * 100) / 100,
      rationale: `Required questionnaire answers satisfied for ${principle}.`,
      answeredQuestionIds,
    };
  });
}
