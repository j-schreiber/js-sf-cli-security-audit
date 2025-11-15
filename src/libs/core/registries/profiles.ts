import { Profile as ProfileMetadata } from '@jsforce/jsforce-node/lib/api/metadata.js';
import RuleRegistry from './ruleRegistry.js';
import EnforcePermissionsOnEntity from './rules/enforcePermissionsOnEntity.js';

export type ResolvedProfile = {
  name: string;
  preset: string;
  metadata: ProfileMetadata;
};

export default class ProfilesRuleRegistry extends RuleRegistry {
  public constructor() {
    super({
      EnforcePermissionClassifications: EnforcePermissionsOnEntity,
    });
  }
}

export const ProfilesRegistry = new ProfilesRuleRegistry();
