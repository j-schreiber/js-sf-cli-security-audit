import { Policies } from '../registry/shape/auditConfigShape.js';

export type AcceptedRisksConfig = Record<Policies, AcceptedPolicyRisks>;

export type AcceptedPolicyRisks = Record<string, AcceptedRuleRisks[]>;

export type AcceptedRuleRisks = {
  identifierMatcher: string[];
  reason: string;
};
