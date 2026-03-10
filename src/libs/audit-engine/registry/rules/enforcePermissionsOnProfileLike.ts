import { Messages } from '@salesforce/core';
import { isNullish } from '../../../../utils.js';
import { PartialPolicyRuleResult, RuleAuditContext } from '../context.types.js';
import RoleManager from '../roles/roleManager.js';
import { ResolvedProfileLike } from '../roles/roleManager.types.js';
import PolicyRule, { RuleOptions } from './policyRule.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.enforceClassificationPresets');

export default class EnforcePermissionsOnProfileLike extends PolicyRule<ResolvedProfileLike> {
  private readonly roleManager;

  public constructor(opts: RuleOptions) {
    super(opts);
    this.roleManager = new RoleManager(opts.auditConfig.definitions.roles, {
      userPermissions: opts.auditConfig.classifications.userPermissions?.permissions,
    });
  }

  public run(context: RuleAuditContext<ResolvedProfileLike>): Promise<PartialPolicyRuleResult> {
    const result = this.initResult();
    const resolvedProfiles = context.resolvedEntities;
    for (const profile of Object.values(resolvedProfiles)) {
      if (!this.roleManager.isValidRole(profile.role)) {
        result.errors.push({
          identifier: [profile.name],
          message: messages.getMessage('error.failed-to-resolve-role', [profile.role]),
        });
        continue;
      }
      if (!isNullish(profile.metadata.userPermissions)) {
        const userPermsScan = this.roleManager.scanPermissions(profile, 'userPermissions', this.auditConfig);
        result.violations.push(...userPermsScan.violations);
        result.warnings.push(...userPermsScan.warnings);
      }
      if (!isNullish(profile.metadata.customPermissions)) {
        const customPermsScan = this.roleManager.scanPermissions(profile, 'customPermissions', this.auditConfig);
        result.violations.push(...customPermsScan.violations);
        result.warnings.push(...customPermsScan.warnings);
      }
    }
    return Promise.resolve(result);
  }
}
