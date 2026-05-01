import type { Question, SGPDPAPrinciple } from '../schema/index.js';

export const SG_PDPA_QUESTIONNAIRE_VERSION = 'sg-pdpa-v1';

export type SGPDPAQuestion = Omit<Question, 'appPrinciple' | 'regulationPrinciple' | 'jurisdiction'> & {
  appPrinciple: SGPDPAPrinciple;
  regulationPrinciple: SGPDPAPrinciple;
  jurisdiction: 'sg-pdpa';
};

const SG_PDPA_QUESTION_BANK_BASE: Array<Omit<SGPDPAQuestion, 'regulationPrinciple' | 'jurisdiction'>> = [
  {
    id: 'Q-SGPDPA-11-001',
    appPrinciple: 'SGPDPA_11',
    question: 'Do you obtain consent before collecting, using, or disclosing personal data when no PDPA exception applies?',
    type: 'yes_no',
    required: true,
    role: 'control',
    passOn: 'yes',
  },
  {
    id: 'Q-SGPDPA-11-002',
    appPrinciple: 'SGPDPA_11',
    question: 'Can individuals withdraw consent through a documented and reasonably accessible process?',
    type: 'yes_no',
    required: true,
    role: 'control',
    passOn: 'yes',
  },
  {
    id: 'Q-SGPDPA-12-001',
    appPrinciple: 'SGPDPA_12',
    question: 'Do you notify individuals of the purposes for which their personal data will be collected, used, or disclosed?',
    type: 'yes_no',
    required: true,
    role: 'control',
    passOn: 'yes',
  },
  {
    id: 'Q-SGPDPA-12-002',
    appPrinciple: 'SGPDPA_12',
    question: 'Are those stated purposes limited to what a reasonable person would consider appropriate in the circumstances?',
    type: 'yes_no',
    required: true,
    role: 'control',
    passOn: 'yes',
  },
  {
    id: 'Q-SGPDPA-24-001',
    appPrinciple: 'SGPDPA_24',
    question: 'Have you implemented reasonable technical and organizational safeguards to protect personal data from unauthorized access, disclosure, copying, modification, or disposal?',
    type: 'yes_no',
    required: true,
    role: 'control',
    passOn: 'yes',
  },
  {
    id: 'Q-SGPDPA-24-002',
    appPrinciple: 'SGPDPA_24',
    question: 'Do you encrypt or otherwise protect sensitive personal data stored in code repositories, fixtures, and backups?',
    type: 'yes_no',
    required: true,
    role: 'control',
    passOn: 'yes',
  },
];

export const SG_PDPA_QUESTION_BANK: SGPDPAQuestion[] = SG_PDPA_QUESTION_BANK_BASE.map((question) => ({
  ...question,
  regulationPrinciple: question.appPrinciple,
  jurisdiction: 'sg-pdpa',
}));

export function getSGPDPAQuestionsForPrinciples(principles: SGPDPAPrinciple[]): SGPDPAQuestion[] {
  return SG_PDPA_QUESTION_BANK.filter((question) => principles.includes(question.regulationPrinciple));
}
