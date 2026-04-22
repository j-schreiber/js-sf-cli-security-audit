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
    this.roleManager = new RoleManager({
      controls: opts.auditConfig.controls,
      shape: opts.auditConfig.shape,
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
      if (!isNullish(profile.metadata)) {
        const profileScanResult = this.roleManager.scanProfileLike(profile);
        result.violations.push(...profileScanResult.violations);
        result.warnings.push(...profileScanResult.warnings);
      }
    }
    return Promise.resolve(result);
  }
}
