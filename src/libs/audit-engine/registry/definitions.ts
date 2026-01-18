import ConnectedAppsPolicy from './policies/connectedApps.js';
import PermissionSetsPolicy from './policies/permissionSets.js';
import ProfilesPolicy from './policies/profiles.js';
import SettingsPolicy from './policies/settings.js';
import UsersPolicy from './policies/users.js';
import Policy from './policy.js';
import { RuleHandlerMap, Constructor } from './ruleRegistry.js';
import AllUsedAppsUnderManagement from './rules/allUsedAppsUnderManagement.js';
import EnforcePermissionPresets from './rules/enforcePermissionPresets.js';
import EnforcePermissionsOnProfileLike from './rules/enforcePermissionsOnProfileLike.js';
import EnforcePermissionsOnUser from './rules/enforcePermissionsOnUser.js';
import NoInactiveUsers from './rules/noInactiveUsers.js';
import NoOtherApexApiLogins from './rules/noOtherApexApiLogins.js';
import NoUserCanSelfAuthorize from './rules/noUserCanSelfAuthorize.js';

type PolicyDefinition = {
  rules?: RuleHandlerMap;
  handler: Constructor<Policy<unknown>>;
};

type PolicyDefinitions = Record<string, PolicyDefinition>;

export const PolicyDefinitions: PolicyDefinitions = {
  permissionSets: {
    handler: PermissionSetsPolicy,
    rules: {
      EnforcePermissionClassifications: EnforcePermissionsOnProfileLike,
    },
  },
  profiles: {
    handler: ProfilesPolicy,
    rules: {
      EnforcePermissionClassifications: EnforcePermissionsOnProfileLike,
    },
  },
  users: {
    handler: UsersPolicy,
    rules: {
      NoOtherApexApiLogins,
      NoInactiveUsers,
      EnforcePermissionClassifications: EnforcePermissionsOnUser,
      EnforcePermissionPresets,
    },
  },
  connectedApps: {
    handler: ConnectedAppsPolicy,
    rules: {
      AllUsedAppsUnderManagement,
      NoUserCanSelfAuthorize,
    },
  },
  settings: {
    handler: SettingsPolicy,
  },
};
