import { PermissionSet } from '@jsforce/jsforce-node/lib/api/metadata.js';
import RuleRegistry from './ruleRegistry.js';
import EnforcePermissionsOnProfileLike from './rules/enforcePermissionsOnProfileLike.js';

export type ResolvedPermissionSet = {
  name: string;
  preset: string;
  metadata: PermissionSet;
};
export default class PermSetsRuleRegistry extends RuleRegistry {
  public constructor() {
    super({
      EnforcePermissionClassifications: EnforcePermissionsOnProfileLike,
    });
  }
}

export const PermissionSetsRegistry = new PermSetsRuleRegistry();
