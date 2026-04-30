import type { CCPAPrinciple } from '../../schema/index.js';

export const CCPAPrincipleInfo: Record<CCPAPrinciple, { shortName: string; obligation: string; citation: string }> = {
  CCPA_100: {
    shortName: 'General Duties',
    obligation: 'Collect PI with notice, limit purpose, limit retention, ensure service provider agreements, maintain reasonable security',
    citation: 'Cal. Civ. Code §1798.100',
  },
  CCPA_105: {
    shortName: 'Right to Delete',
    obligation: 'Consumers can request deletion of their PI; business must delete and direct service providers to delete',
    citation: 'Cal. Civ. Code §1798.105',
  },
  CCPA_106: {
    shortName: 'Right to Correct',
    obligation: 'Consumers can request correction of inaccurate PI',
    citation: 'Cal. Civ. Code §1798.106',
  },
  CCPA_110: {
    shortName: 'Right to Know/Access',
    obligation: 'Consumers can request disclosure of PI collected in the past 12 months',
    citation: 'Cal. Civ. Code §1798.110',
  },
  CCPA_115: {
    shortName: 'Right to Know Sale/Sharing',
    obligation: 'Consumers can request disclosure of PI sold/shared and categories of third parties',
    citation: 'Cal. Civ. Code §1798.115',
  },
  CCPA_120: {
    shortName: 'Right to Opt-Out',
    obligation: 'Consumers can opt-out of sale/sharing of their PI; "Do Not Sell or Share My Personal Information" link required',
    citation: 'Cal. Civ. Code §1798.120',
  },
  CCPA_121: {
    shortName: 'Right to Limit Sensitive PI',
    obligation: 'Consumers can limit use of sensitive PI; "Limit the Use of My Sensitive Personal Information" link required',
    citation: 'Cal. Civ. Code §1798.121',
  },
  CCPA_125: {
    shortName: 'No Retaliation',
    obligation: 'Business must not discriminate against consumers who exercise CCPA rights',
    citation: 'Cal. Civ. Code §1798.125',
  },
  CCPA_130: {
    shortName: 'Notice Requirements',
    obligation: 'Required notices: at collection, privacy policy, right to opt-out; 12-month lookback for access',
    citation: 'Cal. Civ. Code §1798.130',
  },
  CCPA_135: {
    shortName: 'Opt-Out Methods',
    obligation: 'Must honor Global Privacy Control (GPC) signals; must provide opt-out via website, form, or phone',
    citation: 'Cal. Civ. Code §1798.135',
  },
  CCPA_145: {
    shortName: 'Exemptions',
    obligation: 'Business may be exempt if <=$26,625,000 annual revenue, <100K consumers/households, and <=50% annual revenue from selling consumer PI',
    citation: 'Cal. Civ. Code §1798.145',
  },
  CCPA_150: {
    shortName: 'Security Breaches',
    obligation: 'Private right of action for security breaches exposing unencrypted PI; $107-$799/consumer/incident',
    citation: 'Cal. Civ. Code §1798.150',
  },
};
