import { Messages } from '@salesforce/core';
import { PartialPolicyRuleResult, RuleAuditContext } from '../context.types.js';
import { capitalize } from '../../../../utils.js';
import { ResolvedUser } from '../policies/users.js';
import RoleManager from '../roles/roleManager.js';
import { UserPrivilegeLevel } from '../shape/schema.js';
import PolicyRule, { RuleOptions } from './policyRule.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.users');

export default class EnforcePermissionPresets extends PolicyRule<ResolvedUser> {
  private readonly roleManager;

  public constructor(opts: RuleOptions) {
    super(opts);
    this.roleManager = new RoleManager({
      controls: opts.auditConfig.controls,
      shape: {
        userPermissions: opts.auditConfig.classifications.userPermissions?.permissions,
        customPermissions: opts.auditConfig.classifications.customPermissions?.permissions,
      },
    });
  }

  public run(context: RuleAuditContext<ResolvedUser>): Promise<PartialPolicyRuleResult> {
    const result = this.initResult();
    const users = context.resolvedEntities;
    for (const user of Object.values(users)) {
      const profileRole = this.resolveProfileRole(user.profileName);
      this.auditPermissionsEntity(result, user, 'profile', user.profileName, profileRole);
      if (user.assignments) {
        for (const assignment of user.assignments) {
          const permsetRole = this.resolvePermissionSetRole(assignment.permissionSetIdentifier);
          this.auditPermissionsEntity(result, user, 'permission set', assignment.permissionSetIdentifier, permsetRole);
        }
      }
    }
    return Promise.resolve(result);
  }

  private resolveProfileRole(profileName: string): string | undefined {
    return this.auditConfig.classifications.profiles?.profiles[profileName]?.role;
  }

  private resolvePermissionSetRole(permsetName: string): string | undefined {
    return this.auditConfig.classifications.permissionSets?.permissionSets[permsetName]?.role;
  }

  private auditPermissionsEntity(
    result: PartialPolicyRuleResult,
    user: ResolvedUser,
    entityType: string,
    entityIdentifier: string,
    entityPreset?: string
  ): void {
    if (entityPreset) {
      if (entityPreset === UserPrivilegeLevel.UNKNOWN.toString()) {
        result.violations.push({
          identifier: [user.username, entityIdentifier],
          message: messages.getMessage('violations.entity-unknown-but-used', [capitalize(entityType)]),
        });
      } else if (!this.roleManager.isValidRole(entityPreset)) {
        result.violations.push({
          identifier: [user.username, entityIdentifier],
          message: messages.getMessage('violations.invalid-entity-role', [capitalize(entityType), entityPreset]),
        });
      } else if (this.roleManager.isValidRole(entityPreset) && this.roleManager.isValidRole(user.role)) {
        const compareResult = this.roleManager.compare(user.role, entityPreset);
        if (!compareResult.isSuperset) {
          result.violations.push({
            identifier: [user.username, entityIdentifier],
            message: messages.getMessage('violations.entity-not-allowed-for-user-role', [
              user.role,
              entityType,
              entityPreset,
            ]),
          });
        }
      }
    } else {
      result.violations.push({
        identifier: [user.username, entityIdentifier],
        message: messages.getMessage('violations.entity-not-classified-but-used', [capitalize(entityType), entityType]),
      });
    }
  }
}
