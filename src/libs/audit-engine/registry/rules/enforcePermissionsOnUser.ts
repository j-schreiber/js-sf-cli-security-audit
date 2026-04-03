import { Messages } from '@salesforce/core';
import { PartialPolicyRuleResult, RuleAuditContext } from '../context.types.js';
import RoleManager from '../roles/roleManager.js';
import { ScanResult } from '../roles/roleManager.types.js';
import { ResolvedUser } from '../policies/users.js';
import PolicyRule, { RuleOptions } from './policyRule.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.enforceClassificationPresets');

export default class EnforcePermissionsOnUser extends PolicyRule<ResolvedUser> {
  private readonly roleManager;

  public constructor(opts: RuleOptions) {
    super(opts);
    this.roleManager = new RoleManager(opts.auditConfig.definitions.roles, {
      userPermissions: opts.auditConfig.classifications.userPermissions?.permissions,
      customPermissions: opts.auditConfig.classifications.customPermissions?.permissions,
    });
  }

  public run(context: RuleAuditContext<ResolvedUser>): Promise<PartialPolicyRuleResult> {
    const result = this.initResult();
    const users = context.resolvedEntities;
    for (const user of Object.values(users)) {
      if (!this.roleManager.isValidRole(user.role)) {
        result.errors.push({
          identifier: [user.username, user.role],
          message: messages.getMessage('error.failed-to-resolve-role', [user.role]),
        });
        continue;
      }
      const { violations, warnings } = this.scanAssignedPermissionSets(user, user.assignments);
      result.violations.push(...violations);
      result.warnings.push(...warnings);
      if (user.profileMetadata) {
        const profileResult = this.roleManager.scanProfileLike(
          { role: user.role, metadata: user.profileMetadata, name: user.profileName },
          [user.username]
        );
        result.violations.push(...profileResult.violations);
        result.warnings.push(...profileResult.warnings);
      }
    }
    return Promise.resolve(result);
  }

  private scanAssignedPermissionSets(user: ResolvedUser, assignments: ResolvedUser['assignments']): ScanResult {
    const result: ScanResult = { violations: [], warnings: [] };
    if (!assignments) {
      return result;
    }
    for (const assignedPermSet of assignments) {
      if (!assignedPermSet.metadata) {
        continue;
      }
      const permsetScan = this.roleManager.scanProfileLike(
        { role: user.role, metadata: assignedPermSet.metadata, name: assignedPermSet.permissionSetIdentifier },
        [user.username]
      );
      result.violations.push(...permsetScan.violations);
      result.warnings.push(...permsetScan.warnings);
    }
    return result;
  }
}
