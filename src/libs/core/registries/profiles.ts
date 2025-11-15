import { Profile as ProfileMetadata } from '@jsforce/jsforce-node/lib/api/metadata.js';
import RuleRegistry from './ruleRegistry.js';
import EnforcePermissionsOnProfileLike from './rules/enforcePermissionsOnProfileLike.js';

export type ResolvedProfile = {
  name: string;
  preset: string;
  metadata: ProfileMetadata;
};

export default class ProfilesRuleRegistry extends RuleRegistry {
  public constructor() {
    super({
      EnforcePermissionClassifications: EnforcePermissionsOnProfileLike,
    });
  }
}

export const ProfilesRegistry = new ProfilesRuleRegistry();
