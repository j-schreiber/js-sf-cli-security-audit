import { ProfilesRiskPreset } from '../policy-types.js';
import RuleRegistry from './ruleRegistry.js';
import NoInactiveUsers from './rules/noInactiveUsers.js';
import NoOtherApexApiLogins from './rules/noOtherApexApiLogins.js';

export type ResolvedUser = {
  userId: string;
  username: string;
  role: ProfilesRiskPreset;
  assignedPermissionSets: UserPermissionSetAssignment[];
  logins: UserLogins[];
  assignedProfile: string;
  createdDate: number;
  lastLogin?: number;
};

type UserLogins = {
  loginType: string;
  application: string;
  loginCount: number;
  lastLogin: number;
};

type UserPermissionSetAssignment = {
  permissionSetIdentifier: string;
};

export default class UsersRuleRegistry extends RuleRegistry {
  public constructor() {
    super({ NoOtherApexApiLogins, NoInactiveUsers });
  }
}

export const UsersRegistry = new UsersRuleRegistry();
