import { PermissionSet } from '@jsforce/jsforce-node/lib/api/metadata.js';
import RuleRegistry from './ruleRegistry.js';
import EnforcePermissionsOnEntity from './rules/enforcePermissionsOnEntity.js';

export type ResolvedPermissionSet = {
  name: string;
  preset: string;
  metadata: PermissionSet;
};
export default class PermSetsRuleRegistry extends RuleRegistry {
  public constructor() {
    super({
      EnforcePermissionClassifications: EnforcePermissionsOnEntity,
    });
  }
}

export const PermissionSetsRegistry = new PermSetsRuleRegistry();
