import { Messages } from '@salesforce/core';
import { isNullish } from '../../../../utils.js';
import { PartialPolicyRuleResult, RuleAuditContext } from '../context.types.js';
import RoleManager from '../roles/roleManager.js';
import { ResolvedProfileLike, ScanResult } from '../roles/roleManager.types.js';
import RoleChecker from '../roles/roleChecker.js';
import PolicyRule, { RuleOptions } from './policyRule.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.enforceClassificationPresets');

export default class EnforcePermissionsOnProfileLike extends PolicyRule<ResolvedProfileLike> {
  private readonly roleManager;

  public constructor(opts: RuleOptions) {
    super(opts);
    this.roleManager = new RoleManager(opts.auditConfig.definitions.roles, {
      userPermissions: opts.auditConfig.classifications.userPermissions?.permissions,
      customPermissions: opts.auditConfig.classifications.customPermissions?.permissions,
    });
  }

  public run(context: RuleAuditContext<ResolvedProfileLike>): Promise<PartialPolicyRuleResult> {
    const result = this.initResult();
    const resolvedProfiles = context.resolvedEntities;
    const validator = new RoleChecker(context.orgDescribe, this.auditConfig.definitions.roles);
    for (const profile of Object.values(resolvedProfiles)) {
      if (!this.roleManager.isValidRole(profile.role)) {
        result.errors.push({
          identifier: [profile.name],
          message: messages.getMessage('error.failed-to-resolve-role', [profile.role]),
        });
        continue;
      }
      result.warnings.push(...formatWarnings(validator, profile));
      if (!isNullish(profile.metadata)) {
        const profileScanResult = this.roleManager.scanProfileLike(profile);
        result.violations.push(...profileScanResult.violations);
        result.warnings.push(...profileScanResult.warnings);
      }
    }
    return Promise.resolve(result);
  }
}

function formatWarnings(validator: RoleChecker, profileOrPermset: ResolvedProfileLike): ScanResult['warnings'] {
  const warnMessages = validator.checkRoleDefinitionAgainstOrg(profileOrPermset.role);
  return warnMessages.map((message) => ({ identifier: [profileOrPermset.name, profileOrPermset.role], message }));
}
