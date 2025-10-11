import { isEmpty } from '@salesforce/kit';
import { RowLevelPolicyRule } from './interfaces/policyRuleInterfaces.js';
import EnforceClassificationPresets from './rules/enforceClassificationPresets.js';
import { PolicyRuleConfig, ProfilesPolicyFileContent } from './schema.js';
import AuditRunConfig from './interfaces/auditRunConfig.js';
import Policy from './policy.js';

export default class ProfilePolicy extends Policy {
  public constructor(public config: ProfilesPolicyFileContent, public auditContext: AuditRunConfig) {
    super(auditContext, Object.keys(config.profiles), resolveRules(auditContext, config.rules));
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
  // need to rewrite to Object.entries when I need ruleConfig
  for (const ruleName of Object.keys(ruleConfigs!)) {
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
