import { ProfilesRiskPreset } from '../policy-types.js';
import RuleRegistry from './ruleRegistry.js';

export type ResolvedUser = {
  username: string;
  assignedRole: ProfilesRiskPreset;
};
export default class UsersRuleRegistry extends RuleRegistry {
  public constructor() {
    super({});
  }
}

export const UsersRegistry = new UsersRuleRegistry();
