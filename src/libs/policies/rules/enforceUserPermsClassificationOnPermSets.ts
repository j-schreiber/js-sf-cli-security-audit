import { Messages } from '@salesforce/core';
import { PolicyRuleExecutionResult } from '../../audit/types.js';
import { RuleAuditContext } from '../interfaces/policyRuleInterfaces.js';
import { permissionAllowedInPreset, PolicyRiskLevel } from '../types.js';
import { ResolvedPermissionSet } from '../permissionSetPolicy.js';
import PolicyRule, { RuleOptions } from './policyRule.js';

const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.enforceClassificationPresets');

export default class EnforceUserPermsClassificationOnPermSets extends PolicyRule {
  public constructor(opts: RuleOptions) {
    super(opts);
  }

  public run(context: RuleAuditContext): Promise<PolicyRuleExecutionResult> {
    const result = this.initResult();
    const resolvedPermsets = context.resolvedEntities as Record<string, ResolvedPermissionSet>;
    Object.values(resolvedPermsets).forEach((permset) => {
      const userPerms = permset.metadata.userPermissions ?? [];
      userPerms.forEach((userPerm) => {
        const identifier = [permset.name, userPerm.name];
        const classifiedUserPerm = this.resolveUserPermission(userPerm.name);
        if (classifiedUserPerm) {
          if (classifiedUserPerm.classification === PolicyRiskLevel.BLOCKED) {
            result.violations.push({
              identifier,
              message: messages.getMessage('violations.permission-is-blocked'),
            });
          } else if (!permissionAllowedInPreset(classifiedUserPerm.classification, permset.preset)) {
            result.violations.push({
              identifier,
              message: messages.getMessage('violations.classification-preset-mismatch', [
                classifiedUserPerm.classification,
                permset.preset,
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
            message: messages.getMessage('warnings.permission-not-classified-in-permission-set'),
          });
        }
      });
    });
    return Promise.resolve(result);
  }
}
