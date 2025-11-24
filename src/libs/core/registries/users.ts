import { User } from '../mdapi/usersRepository.js';
import { ProfilesRiskPreset } from '../policy-types.js';
import RuleRegistry from './ruleRegistry.js';
import EnforcePermissionsOnUser from './rules/enforcePermissionsOnUser.js';
import NoInactiveUsers from './rules/noInactiveUsers.js';
import NoOtherApexApiLogins from './rules/noOtherApexApiLogins.js';

export type ResolvedUser = User & {
  role: ProfilesRiskPreset;
};

export type UserPermissionSetAssignment = {
  /**
   * Developer name of the permission set
   */
  permissionSetIdentifier: string;
  /**
   * How user got this permission set assigned
   */
  permissionSetSource: 'direct' | 'group';
  /**
   * If permission set is assigned through a group,
   * this is the name of the group.
   */
  groupName?: string;
};

export default class UsersRuleRegistry extends RuleRegistry {
  public constructor() {
    super({
      NoOtherApexApiLogins,
      NoInactiveUsers,
      EnforcePermissionClassifications: EnforcePermissionsOnUser,
    });
  }
}

export const UsersRegistry = new UsersRuleRegistry();
