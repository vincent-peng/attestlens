import type { CCPAPrinciple, Question } from '../schema/index.js';

export const CCPA_QUESTIONNAIRE_VERSION = 'ccpa-cpra-v1';

export type CCPAQuestion = Omit<Question, 'appPrinciple'> & {
  appPrinciple: CCPAPrinciple;
};

export const CCPA_QUESTION_BANK: CCPAQuestion[] = [
  {
    id: 'Q-CCPA100-001',
    appPrinciple: 'CCPA_100',
    question: 'Do you provide notice to consumers at or before the point of collecting their personal information?',
    type: 'yes_no',
    required: true,
    role: 'control',
    passOn: 'yes',
  },
  {
    id: 'Q-CCPA100-002',
    appPrinciple: 'CCPA_100',
    question: 'Do you limit the collection of personal information to what is reasonably necessary for the disclosed purpose?',
    type: 'yes_no',
    required: true,
    role: 'control',
    passOn: 'yes',
  },
  {
    id: 'Q-CCPA100-003',
    appPrinciple: 'CCPA_100',
    question: 'Do you have service provider agreements with all third parties that receive consumer PI?',
    type: 'yes_no',
    required: true,
    role: 'control',
    passOn: 'yes',
  },
  {
    id: 'Q-CCPA100-004',
    appPrinciple: 'CCPA_100',
    question: 'Do you disclose your retention periods for personal information?',
    type: 'yes_no',
    required: false,
    role: 'evidence',
    passOn: 'yes',
    blocking: false,
  },
  {
    id: 'Q-CCPA120-001',
    appPrinciple: 'CCPA_120',
    question: 'Do you provide a "Do Not Sell or Share My Personal Information" link on your homepage?',
    type: 'yes_no',
    required: true,
    role: 'control',
    passOn: 'yes',
  },
  {
    id: 'Q-CCPA121-001',
    appPrinciple: 'CCPA_121',
    question: 'Do you provide a "Limit the Use of My Sensitive Personal Information" link?',
    type: 'yes_no',
    required: true,
    role: 'control',
    passOn: 'yes',
  },
  {
    id: 'Q-CCPA125-001',
    appPrinciple: 'CCPA_125',
    question: 'Do you discriminate against consumers who exercise their CCPA rights (e.g., different pricing, quality of service)?',
    type: 'yes_no',
    required: true,
    role: 'control',
    passOn: 'no',
  },
  {
    id: 'Q-CCPA130-001',
    appPrinciple: 'CCPA_130',
    question: 'Does your privacy policy disclose all categories required by CCPA §1798.130 (consumer rights, designated methods for requests, categories of PI collected, sources, purposes, third-party categories, sale/share information, business purpose disclosures, and sensitive PI categories)?',
    type: 'yes_no',
    required: true,
    role: 'control',
    passOn: 'yes',
  },
  {
    id: 'Q-CCPA135-001',
    appPrinciple: 'CCPA_135',
    question: 'Do you honor Global Privacy Control (GPC) signals as a valid opt-out?',
    type: 'yes_no',
    required: false,
    role: 'evidence',
    passOn: 'yes',
    blocking: false,
  },
  {
    id: 'Q-CCPA145-001',
    appPrinciple: 'CCPA_145',
    question: 'Does your business exceed any CCPA applicability threshold (>$26,625,000 annual revenue, >100K consumers/households, or >50% of annual revenue from selling consumer PI)?',
    type: 'yes_no',
    required: true,
    // "No" passes this gate because it means the business is below the CCPA applicability thresholds.
    // "Yes" confirms CCPA applicability and leaves the substantive controls in scope.
    role: 'applicability_gate',
    passOn: 'no',
  },
  {
    id: 'Q-CCPA150-001',
    appPrinciple: 'CCPA_150',
    question: 'Do you encrypt all personal information at rest and in transit?',
    type: 'yes_no',
    required: true,
    role: 'control',
    passOn: 'yes',
  },
];

export function getCCPAQuestionsForPrinciples(principles: CCPAPrinciple[]): CCPAQuestion[] {
  return CCPA_QUESTION_BANK.filter((question) => principles.includes(question.appPrinciple));
}
