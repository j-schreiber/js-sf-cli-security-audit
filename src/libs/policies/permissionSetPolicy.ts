import { isEmpty } from '@salesforce/kit';
import { RowLevelPolicyRule } from './interfaces/policyRuleInterfaces.js';
import { PermSetsPolicyConfig, PolicyRuleConfig } from './schema.js';
import AuditRunConfig from './interfaces/auditRunConfig.js';
import EnforceClassificationPresetsPermSets from './rules/enforceClassificationPresetsPermSets.js';
import Policy from './policy.js';

export default class PermissionSetPolicy extends Policy {
  public constructor(public config: PermSetsPolicyConfig, public auditContext: AuditRunConfig) {
    super(auditContext);
    this.rules.push(...resolveRules(auditContext, config.rules));
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
        resolved.push(new EnforceClassificationPresetsPermSets(auditContext));
        break;
      default:
        break;
    }
  }
  return resolved;
}
