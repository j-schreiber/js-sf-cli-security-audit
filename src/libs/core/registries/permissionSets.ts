import { PermissionSet } from '@jsforce/jsforce-node/lib/api/metadata.js';
import EnforceUserPermsClassificationOnPermSets from './rules/enforceUserPermsClassificationOnPermSets.js';
import RuleRegistry from './ruleRegistry.js';

export type ResolvedPermissionSet = {
  name: string;
  preset: string;
  metadata: PermissionSet;
};
export default class PermSetsRuleRegistry extends RuleRegistry {
  public constructor() {
    super({
      EnforceUserPermissionClassifications: EnforceUserPermsClassificationOnPermSets,
    });
  }
}

export const PermissionSetsRegistry = new PermSetsRuleRegistry();
