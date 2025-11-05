import { ProfilesRiskPreset } from '../policy-types.js';
import RuleRegistry from './ruleRegistry.js';

export type ResolvedUser = {
  userId: string;
  username: string;
  role: ProfilesRiskPreset;
  assignedPermissionSets: UserPermissionSetAssignment[];
  assignedProfile: string;
};

type UserPermissionSetAssignment = {
  permissionSetIdentifier: string;
};

export default class UsersRuleRegistry extends RuleRegistry {
  public constructor() {
    super({});
  }
}

export const UsersRegistry = new UsersRuleRegistry();
