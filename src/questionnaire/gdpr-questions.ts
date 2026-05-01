import type { GDPRPrinciple, Question } from '../schema/index.js';

export const GDPR_QUESTIONNAIRE_VERSION = 'gdpr-subset-v1';

export type GDPRQuestion = Omit<Question, 'appPrinciple' | 'regulationPrinciple' | 'jurisdiction'> & {
  appPrinciple: GDPRPrinciple;
  regulationPrinciple: GDPRPrinciple;
  jurisdiction: 'eu-gdpr';
};

const GDPR_QUESTION_BANK_BASE: Array<Omit<GDPRQuestion, 'regulationPrinciple' | 'jurisdiction'>> = [
  {
    id: 'Q-GDPR-Art3-001',
    appPrinciple: 'GDPR_Art3',
    question: 'Are you a controller or processor established in the EU, or do you offer goods/services to or monitor the behaviour of data subjects in the Union?',
    type: 'yes_no',
    required: true,
    role: 'applicability_gate',
    passOn: 'no',
  },
  {
    id: 'Q-GDPR-Art5-001',
    appPrinciple: 'GDPR_Art5',
    question: 'Is each processing activity documented with a specific, explicit, and legitimate purpose?',
    type: 'yes_no',
    required: true,
    role: 'control',
    passOn: 'yes',
  },
  {
    id: 'Q-GDPR-Art5-002',
    appPrinciple: 'GDPR_Art5',
    question: 'Do you only collect personal data that is adequate, relevant, and limited to what is necessary?',
    type: 'yes_no',
    required: true,
    role: 'control',
    passOn: 'yes',
  },
  {
    id: 'Q-GDPR-Art6-001',
    appPrinciple: 'GDPR_Art6',
    question: 'Do you have a documented legal basis (consent, contract, legal obligation, vital interests, public interest, or legitimate interest) for each processing activity?',
    type: 'yes_no',
    required: true,
    role: 'control',
    passOn: 'yes',
  },
  {
    id: 'Q-GDPR-Art9-001',
    appPrinciple: 'GDPR_Art9',
    question: 'Do you process special category data (racial/ethnic origin, political opinions, philosophical beliefs, religious beliefs, trade union membership, genetic data, biometric identification data, health data, sex life, or sexual orientation)?',
    type: 'yes_no',
    required: true,
    role: 'applicability_gate',
    passOn: 'no',
  },
  {
    id: 'Q-GDPR-Art9-002',
    appPrinciple: 'GDPR_Art9',
    question: 'If you process special category data, do you have explicit consent or a documented exemption under Art 9(2)?',
    type: 'yes_no',
    required: true,
    role: 'control',
    passOn: 'yes',
    dependsOn: {
      questionId: 'Q-GDPR-Art9-001',
      answers: [true, 'yes'],
    },
  },
  {
    id: 'Q-GDPR-Art13-001',
    appPrinciple: 'GDPR_Art13',
    question: 'Does your privacy notice include: controller identity, purposes, legal basis, recipients, international transfers, retention period, data subject rights, right to withdraw consent, right to complain to DPA, and information about automated decision-making logic?',
    type: 'yes_no',
    required: true,
    role: 'control',
    passOn: 'yes',
  },
  {
    id: 'Q-GDPR-Art15-001',
    appPrinciple: 'GDPR_Art15',
    question: 'Can data subjects access their personal data and obtain information about any automated decision-making logic used?',
    type: 'yes_no',
    required: true,
    role: 'control',
    passOn: 'yes',
  },
  {
    id: 'Q-GDPR-Art17-001',
    appPrinciple: 'GDPR_Art17',
    question: 'Can data subjects request deletion of their personal data, and do you comply without undue delay?',
    type: 'yes_no',
    required: true,
    role: 'control',
    passOn: 'yes',
  },
  {
    id: 'Q-GDPR-Art22-001',
    appPrinciple: 'GDPR_Art22',
    question: 'Do you make solely automated decisions with legal or similarly significant effects?',
    type: 'yes_no',
    required: true,
    role: 'applicability_gate',
    passOn: 'no',
  },
  {
    id: 'Q-GDPR-Art25-001',
    appPrinciple: 'GDPR_Art25',
    question: 'Is data protection implemented by design and by default (e.g., data minimization, pseudonymization, privacy settings enabled by default)?',
    type: 'yes_no',
    required: true,
    role: 'control',
    passOn: 'yes',
  },
  {
    id: 'Q-GDPR-Art32-001',
    appPrinciple: 'GDPR_Art32',
    question: 'Have you implemented appropriate technical and organizational measures to secure personal data (encryption, pseudonymization, resilience, regular testing)?',
    type: 'yes_no',
    required: true,
    role: 'control',
    passOn: 'yes',
  },
  {
    id: 'Q-GDPR-Art33-001',
    appPrinciple: 'GDPR_Art33',
    question: 'Do you have a process to notify the supervisory authority within 72 hours of becoming aware of a personal data breach?',
    type: 'yes_no',
    required: true,
    role: 'control',
    passOn: 'yes',
  },
  {
    id: 'Q-GDPR-Art34-001',
    appPrinciple: 'GDPR_Art34',
    question: 'Do you notify data subjects when a breach is likely to result in high risk to their rights and freedoms?',
    type: 'yes_no',
    required: true,
    role: 'control',
    passOn: 'yes',
  },
  {
    id: 'Q-GDPR-Art35-001',
    appPrinciple: 'GDPR_Art35',
    question: 'Have you conducted a DPIA for any high-risk processing (systematic profiling, large-scale sensitive data, systematic monitoring, new technologies)?',
    type: 'yes_no',
    required: true,
    role: 'control',
    passOn: 'yes',
  },
  {
    id: 'Q-GDPR-Art44-001',
    appPrinciple: 'GDPR_Art44',
    question: 'Do you transfer personal data outside the EEA?',
    type: 'yes_no',
    required: true,
    role: 'applicability_gate',
    passOn: 'no',
  },
  {
    id: 'Q-GDPR-Art44-002',
    appPrinciple: 'GDPR_Art44',
    question: 'If you transfer data outside the EEA, do you have an adequacy decision, Standard Contractual Clauses, Binding Corporate Rules, or other appropriate safeguards?',
    type: 'yes_no',
    required: true,
    role: 'control',
    passOn: 'yes',
    dependsOn: {
      questionId: 'Q-GDPR-Art44-001',
      answers: [true, 'yes'],
    },
  },
];

export const GDPR_QUESTION_BANK: GDPRQuestion[] = GDPR_QUESTION_BANK_BASE.map((question) => ({
  ...question,
  regulationPrinciple: question.appPrinciple,
  jurisdiction: 'eu-gdpr',
}));

export function getGDPRQuestionsForPrinciples(principles: GDPRPrinciple[]): GDPRQuestion[] {
  return GDPR_QUESTION_BANK.filter((question) => principles.includes(question.regulationPrinciple));
}
