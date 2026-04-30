import type { GDPRPrinciple } from '../../schema/index.js';

export const GDPRPrincipleInfo: Record<GDPRPrinciple, { shortName: string; obligation: string; citation: string }> = {
  GDPR_Art3: {
    shortName: 'Territorial Scope',
    obligation: 'If processing EU residents\' data, GDPR applies regardless of processor location',
    citation: 'GDPR Art. 3',
  },
  GDPR_Art5: {
    shortName: 'Processing Principles',
    obligation: 'Lawfulness, fairness, transparency, purpose limitation, data minimization, accuracy, storage limitation, integrity/confidentiality, accountability',
    citation: 'GDPR Art. 5',
  },
  GDPR_Art6: {
    shortName: 'Lawful Basis',
    obligation: 'Each processing activity must have a valid legal basis: consent, contract, legal obligation, vital interests, public interest, or legitimate interest',
    citation: 'GDPR Art. 6',
  },
  GDPR_Art9: {
    shortName: 'Special Categories',
    obligation: 'Special category data (racial, health, biometric, sexual) requires explicit consent or documented exemption under Art 9(2)',
    citation: 'GDPR Art. 9',
  },
  GDPR_Art13: {
    shortName: 'Information to Data Subjects',
    obligation: 'Privacy notice must include: controller identity, purposes, legal basis, recipients, international transfers, retention period, data subject rights, right to withdraw consent, right to complain to DPA, automated decision-making logic',
    citation: 'GDPR Art. 13-14',
  },
  GDPR_Art15: {
    shortName: 'Right of Access',
    obligation: 'Data subjects can access their data and obtain information about automated decision-making logic',
    citation: 'GDPR Art. 15',
  },
  GDPR_Art17: {
    shortName: 'Right to Erasure',
    obligation: 'Data subjects can request deletion of their personal data; controller must erase without undue delay',
    citation: 'GDPR Art. 17',
  },
  GDPR_Art22: {
    shortName: 'Automated Decisions',
    obligation: 'Prohibits solely automated decisions with legal or similarly significant effects without explicit consent, necessary for contract, or authorized by law with suitable safeguards',
    citation: 'GDPR Art. 22',
  },
  GDPR_Art25: {
    shortName: 'Privacy by Design',
    obligation: 'Data protection by design and by default; only process data necessary for specific purpose; minimize collection by default',
    citation: 'GDPR Art. 25',
  },
  GDPR_Art32: {
    shortName: 'Security of Processing',
    obligation: 'Appropriate technical and organizational measures to ensure security: pseudonymization, encryption, resilience, ability to restore, regular testing',
    citation: 'GDPR Art. 32',
  },
  GDPR_Art33: {
    shortName: 'Breach Notification to DPA',
    obligation: 'Notify supervisory authority within 72 hours of becoming aware of a personal data breach',
    citation: 'GDPR Art. 33',
  },
  GDPR_Art34: {
    shortName: 'Breach Notification to Data Subjects',
    obligation: 'Notify data subjects when breach is likely to result in high risk to their rights and freedoms',
    citation: 'GDPR Art. 34',
  },
  GDPR_Art35: {
    shortName: 'DPIA',
    obligation: 'Data Protection Impact Assessment required for high-risk processing: systematic profiling, large-scale sensitive data, systematic monitoring, new technologies',
    citation: 'GDPR Art. 35',
  },
  GDPR_Art44: {
    shortName: 'International Transfers',
    obligation: 'Personal data cannot be transferred outside EEA unless: adequacy decision, appropriate safeguards (SCCs, BCRs), or derogation under Art 49',
    citation: 'GDPR Art. 44-49',
  },
};
