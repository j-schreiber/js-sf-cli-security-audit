import { ProfilesRiskPreset } from '../policy-types.js';
import RuleRegistry from './ruleRegistry.js';
import NoOtherApexApiLogins from './rules/noOtherApexApiLogins.js';

export type ResolvedUser = {
  userId: string;
  username: string;
  role: ProfilesRiskPreset;
  assignedPermissionSets: UserPermissionSetAssignment[];
  logins: UserLogins[];
  assignedProfile: string;
};

type UserLogins = {
  loginType: string;
  application: string;
  loginCount: number;
};

type UserPermissionSetAssignment = {
  permissionSetIdentifier: string;
};

export default class UsersRuleRegistry extends RuleRegistry {
  public constructor() {
    super({ NoOtherApexApiLogins });
  }
}

export const UsersRegistry = new UsersRuleRegistry();
