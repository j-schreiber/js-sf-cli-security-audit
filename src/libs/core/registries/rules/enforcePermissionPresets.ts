import { Messages } from '@salesforce/core';
import UsersRepository from '../../mdapi/usersRepository.js';
import { UserPrivilegeLevel, resolvePresetOrdinalValue } from '../../policy-types.js';
import { PartialPolicyRuleResult, RuleAuditContext } from '../types.js';
import { capitalize } from '../../utils.js';
import { ResolvedUser } from '../users.js';
import PolicyRule, { RuleOptions } from './policyRule.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.users');

export default class EnforcePermissionPresets extends PolicyRule<ResolvedUser> {
  public constructor(opts: RuleOptions) {
    super(opts);
  }

  public async run(context: RuleAuditContext<ResolvedUser>): Promise<PartialPolicyRuleResult> {
    const result = this.initResult();
    const users = context.resolvedEntities;
    const userRepo = new UsersRepository(context.targetOrgConnection);
    // options "with/without metadata - only identifiers"
    const userPerms = await userRepo.resolveUserPermissions(Object.values(users), { withMetadata: false });
    for (const user of Object.values(users)) {
      const profilePreset = this.auditContext.classifications.profiles?.content.profiles[user.profileName];
      auditPermissionsEntity(result, user, 'profile', user.profileName, profilePreset?.role);
      const permsets = userPerms.get(user.userId);
      if (permsets) {
        for (const assignment of permsets.assignedPermissionsets) {
          const permsetPreset =
            this.auditContext.classifications.permissionSets?.content.permissionSets[
              assignment.permissionSetIdentifier
            ];
          auditPermissionsEntity(
            result,
            user,
            'permission set',
            assignment.permissionSetIdentifier,
            permsetPreset?.role
          );
        }
      }
    }
    return result;
  }
}

function auditPermissionsEntity(
  result: PartialPolicyRuleResult,
  user: ResolvedUser,
  entityType: string,
  entityIdentifier: string,
  entityPreset?: UserPrivilegeLevel
): void {
  if (entityPreset) {
    if (entityPreset === UserPrivilegeLevel.UNKNOWN) {
      result.violations.push({
        identifier: [user.username, entityIdentifier],
        message: messages.getMessage('violations.entity-unknown-but-used', [capitalize(entityType)]),
      });
    } else if (resolvePresetOrdinalValue(entityPreset) < resolvePresetOrdinalValue(user.role)) {
      result.violations.push({
        identifier: [user.username, entityIdentifier],
        message: messages.getMessage('violations.entity-not-allowed-for-user-role', [
          user.role,
          entityType,
          entityPreset,
        ]),
      });
    }
  } else {
    result.violations.push({
      identifier: [user.username, entityIdentifier],
      message: messages.getMessage('violations.entity-not-classified-but-used', [capitalize(entityType), entityType]),
    });
  }
}
