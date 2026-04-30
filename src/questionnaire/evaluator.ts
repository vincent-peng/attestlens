import type {
  AssessmentMode,
  Question,
  QuestionnaireEvaluation,
  QuestionnairePrincipleResult,
  QuestionnaireResponse,
  RegulationPrinciple,
} from '../schema/index.js';
import { getApplicableQuestionsForPrinciple, getQuestionById } from './flow.js';
import { QUESTION_BANK } from './questions.js';

const DEFAULT_ASSESSMENT_MODE: AssessmentMode = 'operator_attested';

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

function getQuestionRole(question: Question): NonNullable<Question['role']> {
  return question.role || 'control';
}

function isBlockingQuestion(question: Question): boolean {
  return question.blocking ?? question.required;
}

function getPassOn(question: Question): NonNullable<Question['passOn']> {
  return question.passOn || 'yes';
}

function normalizeBinaryAnswer(value: QuestionnaireResponse['answer']): 'yes' | 'no' | 'na' | undefined {
  if (value === true || value === 'yes') {
    return 'yes';
  }

  if (value === false || value === 'no') {
    return 'no';
  }

  if (value === 'na' || value === 'N/A') {
    return 'na';
  }

  return undefined;
}

function isConditionallyApplicableQuestion(question: Question): boolean {
  return getQuestionRole(question) === 'applicability_gate'
    || Boolean(question.dependsOn)
    || !isBlockingQuestion(question);
}

export function evaluateResponse(
  question: Question,
  answer: QuestionnaireResponse,
): QuestionnaireEvaluation {
  const { answer: value } = answer;
  const role = getQuestionRole(question);

  switch (question.type) {
    case 'yes_no': {
      const normalized = normalizeBinaryAnswer(value);
      const evaluation = role === 'applicability_gate'
        ? normalized === getPassOn(question)
          ? {
              status: 'pass' as const,
              confidence: 0.8,
              rationale: `Applicability gate satisfied for: "${question.question}"`,
            }
          : {
              status: 'pass' as const,
              confidence: 0.72,
              rationale: `Applicability confirmed for: "${question.question}". Follow-up controls remain required.`,
            }
        : normalized === getPassOn(question)
          ? {
              status: 'pass' as const,
              confidence: 0.8,
              rationale: `Compliant response recorded for: "${question.question}"`,
            }
          : {
              status: 'fail' as const,
              confidence: 0.85,
              rationale: `Control requirement not met for: "${question.question}"`,
            };

      return withEvidenceConfidenceBoost(evaluation, answer);
    }

    case 'yes_no_na': {
      const normalized = normalizeBinaryAnswer(value);

      if (normalized === 'na') {
        return withEvidenceConfidenceBoost({
          status: role === 'applicability_gate' ? 'pass' : 'unknown',
          confidence: role === 'applicability_gate' ? 0.7 : 0.35,
          rationale: role === 'applicability_gate'
            ? `Marked not applicable for: "${question.question}"`
            : `Insufficient evidence to resolve: "${question.question}"`,
        }, answer);
      }

      const evaluation = role === 'applicability_gate'
        ? normalized === getPassOn(question)
          ? {
              status: 'pass' as const,
              confidence: 0.78,
              rationale: `Applicability gate satisfied for: "${question.question}"`,
            }
          : {
              status: 'pass' as const,
              confidence: 0.72,
              rationale: `Applicability confirmed for: "${question.question}". Follow-up controls remain required.`,
            }
        : normalized === getPassOn(question)
          ? {
              status: 'pass' as const,
              confidence: 0.8,
              rationale: `Compliant response recorded for: "${question.question}"`,
            }
          : {
              status: 'fail' as const,
              confidence: 0.85,
              rationale: `Control requirement not met for: "${question.question}"`,
            };

      return withEvidenceConfidenceBoost(evaluation, answer);
    }

    case 'multi_choice': {
      const choices = value as string[];
      const failOnOptions = new Set(question.failOnOptions || []);

      if (choices.some((choice) => failOnOptions.has(choice))) {
        return withEvidenceConfidenceBoost({
          status: 'fail',
          confidence: 0.9,
          rationale: `Disallowed response selected for: "${question.question}"`,
        }, answer);
      }

      if (choices.length === 0) {
        return {
          status: 'unknown',
          confidence: 0.3,
          rationale: `No response provided for: "${question.question}"`,
        };
      }

      if (question.minimumSelectedOptions && choices.length < question.minimumSelectedOptions) {
        return withEvidenceConfidenceBoost({
          status: 'fail',
          confidence: 0.82,
          rationale: `Insufficient compliance coverage selected for: "${question.question}"`,
        }, answer);
      }

      return withEvidenceConfidenceBoost({
        status: 'pass',
        confidence: role === 'evidence' ? 0.62 : 0.75,
        rationale: `${choices.length} option${choices.length === 1 ? '' : 's'} selected for: "${question.question}"`,
      }, answer);
    }

    case 'text':
      return {
        status: 'unknown',
        confidence: 0.2,
        rationale: `Free text response requires manual review for: "${question.question}"`,
      };

    default:
      return {
        status: 'unknown',
        confidence: 0.1,
        rationale: 'Unsupported question type',
      };
  }
}

export function evaluateStoredResponse(
  answer: QuestionnaireResponse,
  questions: Question[] = QUESTION_BANK,
): QuestionnaireResponse {
  if (answer.evaluation) {
    return answer;
  }

  const question = getQuestionById(answer.questionId, questions);
  if (!question) {
    return answer;
  }

  return {
    ...answer,
    evaluation: evaluateResponse(question, answer),
  };
}

export function aggregatePrincipleResults(
  principles: RegulationPrinciple[],
  responses: QuestionnaireResponse[],
  questions: Question[] = QUESTION_BANK,
  assessmentMode: AssessmentMode = DEFAULT_ASSESSMENT_MODE,
): QuestionnairePrincipleResult[] {
  const evaluatedResponses = responses.map((response) => evaluateStoredResponse(response, questions));

  return principles.map((principle) => {
    const applicableQuestions = getApplicableQuestionsForPrinciple(
      principle,
      evaluatedResponses,
      questions,
      assessmentMode,
    );
    const answeredResponses = applicableQuestions
      .map((question) => evaluatedResponses.find((response) => response.questionId === question.id))
      .filter((response): response is QuestionnaireResponse => Boolean(response));
    const answeredQuestionIds = answeredResponses.map((response) => response.questionId);
    const blockingQuestions = applicableQuestions.filter((question) => isBlockingQuestion(question));
    const nonBlockingQuestions = applicableQuestions.filter((question) => !isBlockingQuestion(question));
    const unansweredBlocking = blockingQuestions.filter((question) => !answeredQuestionIds.includes(question.id));
    const blockingResponses = answeredResponses.filter((response) =>
      blockingQuestions.some((question) => question.id === response.questionId),
    );
    const blockingEvaluations = blockingResponses
      .map((response) => response.evaluation)
      .filter((evaluation): evaluation is QuestionnaireEvaluation => Boolean(evaluation));
    const failEvaluations = blockingEvaluations.filter((evaluation) => evaluation.status === 'fail');
    const unknownEvaluations = blockingEvaluations.filter((evaluation) => evaluation.status === 'unknown');
    const supportingResponses = answeredResponses.filter((response) =>
      nonBlockingQuestions.some((question) => question.id === response.questionId),
    );

    if (unansweredBlocking.length > 0) {
      return {
        principle,
        status: 'unknown',
        confidence: 0.0,
        rationale: `Awaiting blocking questionnaire answers: ${unansweredBlocking.map((question) => question.id).join(', ')}`,
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

    if (unknownEvaluations.length > 0) {
      return {
        principle,
        status: 'unknown',
        confidence: 0.35,
        rationale: unknownEvaluations[0]!.rationale,
        answeredQuestionIds,
      };
    }

    if (blockingEvaluations.length === 0) {
      return {
        principle,
        status: 'unknown',
        confidence: 0.0,
        rationale: 'No applicable blocking questionnaire answers have been recorded yet.',
        answeredQuestionIds,
      };
    }

    const averageConfidence = blockingEvaluations.reduce((sum, evaluation) => sum + evaluation.confidence, 0) / blockingEvaluations.length;
    const evidenceBoost = supportingResponses.length > 0 ? 0.05 : 0;
    const rationale = supportingResponses.length > 0
      ? `Blocking questionnaire answers satisfied for ${principle}, with ${supportingResponses.length} supporting evidence response${supportingResponses.length === 1 ? '' : 's'}.`
      : `Blocking questionnaire answers satisfied for ${principle}.`;

    return {
      principle,
      status: 'pass',
      confidence: Math.round(Math.min(0.95, averageConfidence + evidenceBoost) * 100) / 100,
      rationale,
      answeredQuestionIds,
    };
  });
}
