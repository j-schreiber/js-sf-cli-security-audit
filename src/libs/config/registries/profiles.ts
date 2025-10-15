import EnforceCustomPermsClassificationOnProfiles from '../../policies/rules/enforceCustomPermsClassificationOnProfiles.js';
import EnforceUserPermsClassificationOnProfiles from '../../policies/rules/enforceUserPermsClassificationOnProfiles.js';
import RuleRegistry from './ruleRegistry.js';

export default class ProfilesRuleRegistry extends RuleRegistry {
  public constructor() {
    super({
      EnforceCustomPermissionClassifications: EnforceCustomPermsClassificationOnProfiles,
      EnforceUserPermissionClassifications: EnforceUserPermsClassificationOnProfiles,
    });
  }
}
