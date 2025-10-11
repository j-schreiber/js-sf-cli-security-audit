import { isEmpty } from '@salesforce/kit';
import { RowLevelPolicyRule } from './interfaces/policyRuleInterfaces.js';
import { PermSetsPolicyFileContent, PolicyRuleConfig } from './schema.js';
import AuditRunConfig from './interfaces/auditRunConfig.js';
import EnforceClassificationPresetsPermSets from './rules/enforceClassificationPresetsPermSets.js';
import Policy from './policy.js';

export default class PermissionSetPolicy extends Policy {
  public constructor(public config: PermSetsPolicyFileContent, public auditContext: AuditRunConfig) {
    super(auditContext, Object.keys(config.permissionSets), resolveRules(auditContext, config.rules));
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
        resolved.push(new EnforceClassificationPresetsPermSets(auditContext));
        break;
      default:
        break;
    }
  }
  return resolved;
}
