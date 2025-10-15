import { Messages } from '@salesforce/core';
import { PolicyRuleExecutionResult } from '../../audit/types.js';
import { RuleAuditContext } from '../interfaces/policyRuleInterfaces.js';
import { permissionAllowedInPreset, PolicyRiskLevel } from '../types.js';
import { ResolvedProfile } from '../profilePolicy.js';
import PolicyRule, { RuleOptions } from './policyRule.js';

const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.enforceClassificationPresets');

export default class EnforceUserPermsClassificationOnProfiles extends PolicyRule {
  public constructor(opts: RuleOptions) {
    super(opts);
  }

  public run(context: RuleAuditContext): Promise<PolicyRuleExecutionResult> {
    const result = this.initResult();
    const resolvedProfiles = context.resolvedEntities as Record<string, ResolvedProfile>;
    Object.values(resolvedProfiles).forEach((profile) => {
      profile.metadata.userPermissions.forEach((userPerm) => {
        const identifier = [profile.name, userPerm.name];
        const classifiedUserPerm = this.auditContext.resolveUserPermission(userPerm.name);
        if (classifiedUserPerm) {
          if (classifiedUserPerm.classification === PolicyRiskLevel.BLOCKED) {
            result.violations.push({
              identifier,
              message: messages.getMessage('violations.permission-is-blocked'),
            });
          } else if (!permissionAllowedInPreset(classifiedUserPerm.classification, profile.preset)) {
            result.violations.push({
              identifier,
              message: messages.getMessage('violations.classification-preset-mismatch', [
                classifiedUserPerm.classification,
                profile.preset,
              ]),
            });
          } else if (classifiedUserPerm.classification === PolicyRiskLevel.UNKNOWN) {
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
