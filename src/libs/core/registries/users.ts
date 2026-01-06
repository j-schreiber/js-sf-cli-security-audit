import { User } from '../mdapi/usersRepository.js';
import { UserPrivilegeLevel } from '../policy-types.js';
import RuleRegistry from './ruleRegistry.js';
import EnforcePermissionPresets from './rules/enforcePermissionPresets.js';
import EnforcePermissionsOnUser from './rules/enforcePermissionsOnUser.js';
import NoInactiveUsers from './rules/noInactiveUsers.js';
import NoOtherApexApiLogins from './rules/noOtherApexApiLogins.js';

export type ResolvedUser = User & {
  role: UserPrivilegeLevel;
};

export default class UsersRuleRegistry extends RuleRegistry {
  public constructor() {
    super({
      NoOtherApexApiLogins,
      NoInactiveUsers,
      EnforcePermissionClassifications: EnforcePermissionsOnUser,
      EnforcePermissionPresets,
    });
  }
}

export const UsersRegistry = new UsersRuleRegistry();
