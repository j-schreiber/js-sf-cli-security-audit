import { Messages } from '@salesforce/core';
import { PartialPolicyRuleResult, RuleAuditContext } from '../types.js';
import { isNullish } from '../../utils.js';
import { ResolvedProfile } from '../profiles.js';
import { PermissionRiskLevel } from '../../classification-types.js';
import { permissionAllowedInPreset } from '../../policy-types.js';
import PolicyRule, { RuleOptions } from './policyRule.js';

const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.enforceClassificationPresets');

export default class EnforceUserPermsClassificationOnProfiles extends PolicyRule<ResolvedProfile> {
  public constructor(opts: RuleOptions) {
    super(opts);
  }

  public run(context: RuleAuditContext<ResolvedProfile>): Promise<PartialPolicyRuleResult> {
    const result = this.initResult();
    const resolvedProfiles = context.resolvedEntities;
    Object.values(resolvedProfiles).forEach((profile) => {
      if (!isNullish(profile.metadata.userPermissions)) {
        profile.metadata.userPermissions.forEach((userPerm) => {
          const identifier = [profile.name, userPerm.name];
          const classifiedUserPerm = this.resolveUserPermission(userPerm.name);
          if (classifiedUserPerm) {
            if (classifiedUserPerm.classification === PermissionRiskLevel.BLOCKED) {
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
            } else if (classifiedUserPerm.classification === PermissionRiskLevel.UNKNOWN) {
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
      }
    });
    return Promise.resolve(result);
  }
}
