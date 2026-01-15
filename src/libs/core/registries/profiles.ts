import RuleRegistry from './ruleRegistry.js';
import EnforcePermissionsOnProfileLike from './rules/enforcePermissionsOnProfileLike.js';

export default class ProfilesRuleRegistry extends RuleRegistry {
  public constructor() {
    super({
      EnforcePermissionClassifications: EnforcePermissionsOnProfileLike,
    });
  }
}

export const ProfilesRegistry = new ProfilesRuleRegistry();
