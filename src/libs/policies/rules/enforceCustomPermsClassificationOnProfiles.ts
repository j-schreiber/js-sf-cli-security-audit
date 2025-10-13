import { Messages } from '@salesforce/core';
import { PolicyRuleExecutionResult } from '../../audit/types.js';
import { RuleAuditContext } from '../interfaces/policyRuleInterfaces.js';
import { permissionAllowedInPreset, PolicyRiskLevel } from '../types.js';
import AuditRunConfig from '../interfaces/auditRunConfig.js';
import { ResolvedProfile } from '../profilePolicy.js';
import PolicyRule from './policyRule.js';

const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.enforceClassificationPresets');

export default class EnforceCustomPermsClassificationOnProfiles extends PolicyRule {
  public constructor(auditContext: AuditRunConfig) {
    super({
      auditContext,
      ruleDisplayName: 'EnforceCustomPermissionClassifications',
    });
  }

  public run(context: RuleAuditContext): Promise<PolicyRuleExecutionResult> {
    const result = this.initResult();
    const resolvedProfiles = context.resolvedEntities as Record<string, ResolvedProfile>;
    Object.values(resolvedProfiles).forEach((profile) => {
      const customPerms = profile.metadata.customPermissions ?? [];
      customPerms.forEach((perm) => {
        const identifier = [profile.name, perm.name];
        const classifiedPerm = this.auditContext.resolveCustomPermission(perm.name);
        if (classifiedPerm) {
          if (classifiedPerm.classification === PolicyRiskLevel.BLOCKED) {
            result.violations.push({
              identifier,
              message: messages.getMessage('violations.permission-is-blocked'),
            });
          } else if (!permissionAllowedInPreset(classifiedPerm.classification, profile.preset)) {
            result.violations.push({
              identifier,
              message: messages.getMessage('violations.classification-preset-mismatch', [
                classifiedPerm.classification,
                profile.preset,
              ]),
            });
          } else if (classifiedPerm.classification === PolicyRiskLevel.UNKNOWN) {
            result.warnings.push({
              identifier,
              message: messages.getMessage('warnings.permission-unknown'),
            });
          }
        } else {
          result.warnings.push({
            identifier,
            message: messages.getMessage('warnings.permission-not-classified-in-profile'),
          });
        }
      });
    });
    return Promise.resolve(result);
  }
}
