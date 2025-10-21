import { EntityResolveError, PolicyRuleSkipResult } from '../../audit/types.js';
import { RowLevelPolicyRule } from '../../policies/interfaces/policyRuleInterfaces.js';

export type RegistryRuleResolveResult = {
  enabledRules: Array<RowLevelPolicyRule<unknown>>;
  skippedRules: PolicyRuleSkipResult[];
  resolveErrors: EntityResolveError[];
};
