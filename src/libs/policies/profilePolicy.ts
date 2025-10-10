import { isEmpty } from '@salesforce/kit';
import { AuditPolicyResult, PolicyRuleExecutionResult } from '../audit/types.js';
import { AuditContext, Policy, RowLevelPolicyRule } from './interfaces/policyRuleInterfaces.js';
import EnforceClassificationPresets from './rules/enforceClassificationPresets.js';
import { PolicyRuleConfig, ProfilesPolicyConfig } from './schema.js';
import AuditRunConfig from './interfaces/auditRunConfig.js';

export default class ProfilePolicy implements Policy {
  private rules: RowLevelPolicyRule[];

  public constructor(public config: ProfilesPolicyConfig, public auditContext: AuditRunConfig) {
    this.rules = resolveRules(auditContext, config.rules);
  }

  public async run(context: AuditContext): Promise<AuditPolicyResult> {
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
  auditContext: AuditRunConfig,
  ruleConfigs?: Record<string, PolicyRuleConfig>
): RowLevelPolicyRule[] {
  if (isEmpty(ruleConfigs)) {
    return [];
  }
  const resolved = new Array<RowLevelPolicyRule>();
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  for (const [ruleName, ruleConfig] of Object.entries(ruleConfigs!)) {
    switch (ruleName) {
      case 'EnforceClassificationPresets':
        resolved.push(new EnforceClassificationPresets(auditContext));
        break;
      default:
        break;
    }
  }
  return resolved;
}
