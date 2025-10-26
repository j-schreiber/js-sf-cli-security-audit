import { Profile as ProfileMetadata } from '@jsforce/jsforce-node/lib/api/metadata.js';
import EnforceCustomPermsClassificationOnProfiles from './rules/enforceCustomPermsClassificationOnProfiles.js';
import EnforceUserPermsClassificationOnProfiles from './rules/enforceUserPermsClassificationOnProfiles.js';
import RuleRegistry from './ruleRegistry.js';

export type ResolvedProfile = {
  name: string;
  preset: string;
  metadata: ProfileMetadata;
};

export default class ProfilesRuleRegistry extends RuleRegistry {
  public constructor() {
    super({
      EnforceCustomPermissionClassifications: EnforceCustomPermsClassificationOnProfiles,
      EnforceUserPermissionClassifications: EnforceUserPermsClassificationOnProfiles,
    });
  }
}

export const ProfilesRegistry = new ProfilesRuleRegistry();
