import { Messages } from '@salesforce/core';
import { PartialPolicyRuleResult, RuleAuditContext } from '../types.js';
import { ResolvedProfile } from '../profiles.js';
import { PermissionRiskLevel } from '../../classification-types.js';
import { permissionAllowedInPreset } from '../../policy-types.js';
import PolicyRule, { RuleOptions } from './policyRule.js';
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.enforceClassificationPresets');

export default class EnforceCustomPermsClassificationOnProfiles extends PolicyRule<ResolvedProfile> {
  public constructor(opts: RuleOptions) {
    super(opts);
  }

  public run(context: RuleAuditContext<ResolvedProfile>): Promise<PartialPolicyRuleResult> {
    const result = this.initResult();
    const resolvedProfiles = context.resolvedEntities;
    Object.values(resolvedProfiles).forEach((profile) => {
      const customPerms = profile.metadata.customPermissions ?? [];
      customPerms.forEach((perm) => {
        const identifier = [profile.name, perm.name];
        const classifiedPerm = this.resolveCustomPermission(perm.name);
        if (classifiedPerm) {
          if (classifiedPerm.classification === PermissionRiskLevel.BLOCKED) {
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
          } else if (classifiedPerm.classification === PermissionRiskLevel.UNKNOWN) {
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
