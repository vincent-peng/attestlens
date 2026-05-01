import { describe, expect, it } from 'vitest';

import { APPInfo, JurisdictionInfo } from '../schema/index.js';
import { CCPAPrincipleInfo } from '../scanner/rules/ccpa-principles.js';
import { GDPRPrincipleInfo } from '../scanner/rules/gdpr-principles.js';
import { getRegistry } from './registry.js';

describe('getRegistry', () => {
  it('builds the AU registry from APPInfo', () => {
    const registry = getRegistry('au-privacy-act');

    expect(registry.jurisdiction).toBe('au-privacy-act');
    expect(registry.order[0]).toBe('APP_1');
    expect(registry.order.at(-1)).toBe('NDB');
    expect(registry.principles.APP_11).toEqual({
      shortName: APPInfo.APP_11.shortName,
      fullName: APPInfo.APP_11.shortName,
      obligation: APPInfo.APP_11.obligation,
      citation: JurisdictionInfo['au-privacy-act'].citation,
    });
  });

  it('builds the CCPA registry from CCPAPrincipleInfo', () => {
    const registry = getRegistry('us-ccpa');

    expect(registry.jurisdiction).toBe('us-ccpa');
    expect(registry.order).toEqual(Object.keys(CCPAPrincipleInfo));
    expect(registry.principles.CCPA_150).toEqual({
      shortName: CCPAPrincipleInfo.CCPA_150.shortName,
      fullName: CCPAPrincipleInfo.CCPA_150.shortName,
      obligation: CCPAPrincipleInfo.CCPA_150.obligation,
      citation: CCPAPrincipleInfo.CCPA_150.citation,
    });
  });

  it('builds the GDPR registry from GDPRPrincipleInfo', () => {
    const registry = getRegistry('eu-gdpr');

    expect(registry.jurisdiction).toBe('eu-gdpr');
    expect(registry.order).toEqual(Object.keys(GDPRPrincipleInfo));
    expect(registry.principles.GDPR_Art32).toEqual({
      shortName: GDPRPrincipleInfo.GDPR_Art32.shortName,
      fullName: GDPRPrincipleInfo.GDPR_Art32.shortName,
      obligation: GDPRPrincipleInfo.GDPR_Art32.obligation,
      citation: GDPRPrincipleInfo.GDPR_Art32.citation,
    });
  });
});
