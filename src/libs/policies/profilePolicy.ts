import { isEmpty } from '@salesforce/kit';
import { AuditPolicyResult, PolicyRuleExecutionResult } from '../audit/types.js';
import { RowLevelPolicyRule, RuleExecutionContext } from './interfaces/policyRuleInterfaces.js';
import EnforceClassificationPresets from './rules/enforceClassificationPresets.js';
import { PermissionSetLikeMap, PolicyRuleConfig, ProfilesPolicyConfig } from './schema.js';

export default class ProfilePolicy {
  private rules: RowLevelPolicyRule[];

  public constructor(public config: ProfilesPolicyConfig) {
    this.rules = resolveRules(config.rules, config.profiles);
  }

  public async run(context: RuleExecutionContext): Promise<AuditPolicyResult> {
    const ruleResultPromises = Array<Promise<PolicyRuleExecutionResult>>();
    for (const rule of this.rules) {
      ruleResultPromises.push(rule.run(context));
    }
    const ruleResults = await Promise.all(ruleResultPromises);
    const executedRules: Record<string, PolicyRuleExecutionResult> = {};
    ruleResults.forEach((rr) => (executedRules[rr.ruleName] = rr));
    return { isCompliant: true, enabled: true, executedRules, skippedRules: [] };
  }
}

function resolveRules(
  ruleConfigs?: Record<string, PolicyRuleConfig>,
  profiles?: PermissionSetLikeMap
): RowLevelPolicyRule[] {
  if (isEmpty(ruleConfigs)) {
    return [];
  }
  const resolved = new Array<RowLevelPolicyRule>();
  for (const [ruleName, ruleConfig] of Object.entries(ruleConfigs!)) {
    switch (ruleName) {
      case 'EnforceClassificationPresets':
        resolved.push(new EnforceClassificationPresets(ruleConfig, profiles));
        break;
      default:
        break;
    }
  }
  return resolved;
}
