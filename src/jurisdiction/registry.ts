import {
  APPInfo,
  APPPrinciple,
  type APPPrinciple as APPPrincipleType,
  Jurisdiction,
  JurisdictionInfo,
  type Jurisdiction as JurisdictionType,
  type RegulationPrinciple,
} from '../schema/index.js';
import { CCPAPrincipleInfo } from '../scanner/rules/ccpa-principles.js';
import { GDPRPrincipleInfo } from '../scanner/rules/gdpr-principles.js';

export interface PrincipleInfo {
  shortName: string;
  fullName: string;
  obligation: string;
  citation?: string;
}

export interface PrincipleRegistry {
  jurisdiction: JurisdictionType;
  principles: Record<RegulationPrinciple, PrincipleInfo>;
  order: RegulationPrinciple[];
}

const AU_ORDER: APPPrincipleType[] = APPPrinciple.options;
const CCPA_ORDER: RegulationPrinciple[] = Object.keys(CCPAPrincipleInfo);
const GDPR_ORDER: RegulationPrinciple[] = Object.keys(GDPRPrincipleInfo);

const AU_REGISTRY: PrincipleRegistry = {
  jurisdiction: 'au-privacy-act',
  principles: Object.fromEntries(
    AU_ORDER.map((principle) => [
      principle,
      {
        shortName: APPInfo[principle].shortName,
        fullName: APPInfo[principle].shortName,
        obligation: APPInfo[principle].obligation,
        citation: JurisdictionInfo['au-privacy-act'].citation,
      },
    ]),
  ),
  order: AU_ORDER,
};

const CCPA_REGISTRY: PrincipleRegistry = {
  jurisdiction: 'us-ccpa',
  principles: Object.fromEntries(
    CCPA_ORDER.map((principle) => [
      principle,
      {
        shortName: CCPAPrincipleInfo[principle as keyof typeof CCPAPrincipleInfo].shortName,
        fullName: CCPAPrincipleInfo[principle as keyof typeof CCPAPrincipleInfo].shortName,
        obligation: CCPAPrincipleInfo[principle as keyof typeof CCPAPrincipleInfo].obligation,
        citation: CCPAPrincipleInfo[principle as keyof typeof CCPAPrincipleInfo].citation,
      },
    ]),
  ),
  order: CCPA_ORDER,
};

const GDPR_REGISTRY: PrincipleRegistry = {
  jurisdiction: 'eu-gdpr',
  principles: Object.fromEntries(
    GDPR_ORDER.map((principle) => [
      principle,
      {
        shortName: GDPRPrincipleInfo[principle as keyof typeof GDPRPrincipleInfo].shortName,
        fullName: GDPRPrincipleInfo[principle as keyof typeof GDPRPrincipleInfo].shortName,
        obligation: GDPRPrincipleInfo[principle as keyof typeof GDPRPrincipleInfo].obligation,
        citation: GDPRPrincipleInfo[principle as keyof typeof GDPRPrincipleInfo].citation,
      },
    ]),
  ),
  order: GDPR_ORDER,
};

const REGISTRIES: Record<JurisdictionType, PrincipleRegistry> = {
  'au-privacy-act': AU_REGISTRY,
  'us-ccpa': CCPA_REGISTRY,
  'eu-gdpr': GDPR_REGISTRY,
};

export function getRegistry(jurisdiction: JurisdictionType): PrincipleRegistry {
  return REGISTRIES[Jurisdiction.parse(jurisdiction)];
}
