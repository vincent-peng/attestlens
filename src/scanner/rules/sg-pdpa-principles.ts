import type { SGPDPAPrinciple } from '../../schema/index.js';

export const SGPDPAPrincipleInfo: Record<SGPDPAPrinciple, { shortName: string; obligation: string; citation: string }> = {
  SGPDPA_11: {
    shortName: 'Consent Obligation',
    obligation: 'Obtain valid consent before collecting, using, or disclosing personal data unless an exception applies',
    citation: 'PDPA 2012 (Singapore) s 11-17',
  },
  SGPDPA_12: {
    shortName: 'Purpose Limitation',
    obligation: 'Collect, use, or disclose personal data only for purposes a reasonable person would consider appropriate and that were notified to the individual',
    citation: 'PDPA 2012 (Singapore) s 18',
  },
  SGPDPA_24: {
    shortName: 'Protection Obligation',
    obligation: 'Make reasonable security arrangements to prevent unauthorized access, collection, use, disclosure, copying, modification, disposal, or similar risks',
    citation: 'PDPA 2012 (Singapore) s 24',
  },
};
