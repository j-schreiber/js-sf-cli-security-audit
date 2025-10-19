import EnforceUserPermsClassificationOnPermSets from '../../policies/rules/enforceUserPermsClassificationOnPermSets.js';
import RuleRegistry from './ruleRegistry.js';

export default class PermSetsRuleRegistry extends RuleRegistry {
  public constructor() {
    super({
      EnforceUserPermissionClassifications: EnforceUserPermsClassificationOnPermSets,
    });
  }
}

export const PermissionSetsRegistry = new PermSetsRuleRegistry();
