import { Messages } from '@salesforce/core';
import { PartialPolicyRuleResult, RuleAuditContext } from '../types.js';
import { ResolvedPermissionSet } from '../permissionSets.js';
import { PermissionRiskLevel } from '../../classification-types.js';
import { permissionAllowedInPreset } from '../../policy-types.js';
import PolicyRule, { RuleOptions } from './policyRule.js';

const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.enforceClassificationPresets');

export default class EnforceUserPermsClassificationOnPermSets extends PolicyRule<ResolvedPermissionSet> {
  public constructor(opts: RuleOptions) {
    super(opts);
  }

  public run(context: RuleAuditContext<ResolvedPermissionSet>): Promise<PartialPolicyRuleResult> {
    const result = this.initResult();
    const resolvedPermsets = context.resolvedEntities;
    Object.values(resolvedPermsets).forEach((permset) => {
      const userPerms = permset.metadata.userPermissions ?? [];
      userPerms.forEach((userPerm) => {
        const identifier = [permset.name, userPerm.name];
        const classifiedUserPerm = this.resolveUserPermission(userPerm.name);
        if (classifiedUserPerm) {
          if (classifiedUserPerm.classification === PermissionRiskLevel.BLOCKED) {
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
          } else if (classifiedUserPerm.classification === PermissionRiskLevel.UNKNOWN) {
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
