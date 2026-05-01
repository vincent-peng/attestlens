import { checkbox, input, select } from '@inquirer/prompts';
import chalk from 'chalk';

import {
  type AssessmentMode,
  type AttestLensFinding,
  type Question,
  type QuestionnaireResponse,
} from '../schema/index.js';
import { getRegistry } from '../jurisdiction/registry.js';

export type AttestationPromptResult =
  | { kind: 'save_and_exit' }
  | {
      kind: 'answer';
      answer: QuestionnaireResponse['answer'];
      note?: string;
      evidenceRefs?: string[];
      answeredBy?: string;
    };

export interface AttestationPromptContext {
  progress: {
    current: number;
    total: number;
  };
  sessionPath: string;
  relevantFindings: AttestLensFinding[];
}

export interface AttestationAssessmentModeContext {
  targetKind: 'path' | 'url';
  targetName: string;
}

export interface AttestationPromptRunner {
  promptAssessmentMode(context: AttestationAssessmentModeContext): Promise<AssessmentMode>;
  prompt(question: Question, context: AttestationPromptContext): Promise<AttestationPromptResult>;
}

function normalizeEvidenceRefs(rawValue: string): string[] | undefined {
  const refs = rawValue
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
  return refs.length > 0 ? refs : undefined;
}

function printQuestionContext(question: Question, context: AttestationPromptContext): void {
  const principleLabel = getPrincipleLabel(question.regulationPrinciple);
  console.log('');
  console.log(chalk.bold.cyan(`${question.regulationPrinciple} — ${principleLabel}`));
  console.log(chalk.gray(`Question ${context.progress.current} of ${context.progress.total}`));
  console.log(chalk.gray(`Session: ${context.sessionPath}`));

  if (question.helpText) {
    console.log(chalk.gray(question.helpText));
  }

  if (context.relevantFindings.length > 0) {
    console.log(chalk.yellow('\nRelevant scan context:'));
    for (const finding of context.relevantFindings.slice(0, 3)) {
      console.log(
        chalk.yellow(
          `  [${finding.severity.toUpperCase()}] ${finding.sourceRule}: ${finding.title}`,
        ),
      );
    }
  }
}

function getPrincipleLabel(principle: string): string {
  for (const jurisdiction of ['au-privacy-act', 'us-ccpa', 'eu-gdpr', 'sg-pdpa'] as const) {
    const info = getRegistry(jurisdiction).principles[principle];
    if (info) {
      return info.shortName;
    }
  }

  return principle;
}

export function createInteractivePromptRunner(): AttestationPromptRunner {
  return {
    async promptAssessmentMode(context) {
      if (!process.stdin.isTTY || !process.stdout.isTTY) {
        throw new Error('Attestation requires an interactive terminal.');
      }

      console.log('');
      console.log(chalk.bold.cyan('Assessment Basis'));
      console.log(chalk.gray(`Target: ${context.targetName} (${context.targetKind === 'url' ? 'URL' : 'path'})`));
      console.log(chalk.gray('Choose the evidence basis for this attestation. This choice is frozen into the saved session.'));

      return select<AssessmentMode>({
        message: 'Which assessment basis best fits this run?',
        choices: [
          {
            name: 'Artifact-only review',
            value: 'artifact_only',
            description: 'Saved/public artifact review without live operator or process evidence.',
          },
          {
            name: 'Codebase-only review',
            value: 'codebase_only',
            description: 'Local repo/code scan without observed deployment or operational process evidence.',
          },
          {
            name: 'Operator-attested review',
            value: 'operator_attested',
            description: 'Reviewer has live organisational/process knowledge and is attesting those controls.',
          },
        ],
      });
    },

    async prompt(question, context) {
      if (!process.stdin.isTTY || !process.stdout.isTTY) {
        throw new Error('Attestation requires an interactive terminal.');
      }

      printQuestionContext(question, context);

      const action = await select({
        message: 'Next action',
        choices: [
          { name: 'Answer this question', value: 'answer' },
          { name: 'Save and exit', value: 'save_and_exit' },
        ],
      });

      if (action === 'save_and_exit') {
        return { kind: 'save_and_exit' };
      }

      let answer: QuestionnaireResponse['answer'];
      switch (question.type) {
        case 'yes_no':
          answer = await select<boolean>({
            message: question.question,
            choices: [
              { name: 'Yes', value: true },
              { name: 'No', value: false },
            ],
          });
          break;
        case 'yes_no_na':
          answer = await select<boolean | 'na'>({
            message: question.question,
            choices: [
              { name: 'Yes', value: true },
              { name: 'No', value: false },
              { name: 'Not applicable', value: 'na' },
            ],
          });
          break;
        case 'multi_choice':
          answer = await checkbox({
            message: question.question,
            choices: (question.options || []).map((option) => ({ name: option, value: option })),
            required: question.required,
          });
          break;
        case 'text':
          answer = await input({
            message: question.question,
          });
          break;
        default:
          throw new Error(`Unsupported question type: ${question.type}`);
      }

      const note = (await input({
        message: 'Optional note (leave blank to skip)',
        default: '',
      })).trim() || undefined;

      const evidenceRefs = normalizeEvidenceRefs(await input({
        message: 'Optional evidence refs (comma-separated paths or URLs)',
        default: '',
      }));

      return {
        kind: 'answer',
        answer,
        note,
        evidenceRefs,
      };
    },
  };
}
