import ConnectedAppsPolicy from './policies/connectedApps.js';
import PermissionSetsPolicy from './policies/permissionSets.js';
import ProfilesPolicy from './policies/profiles.js';
import SettingsPolicy from './policies/settings.js';
import UsersPolicy from './policies/users.js';
import RuleRegistry, { RuleHandlerMap, Constructor } from './ruleRegistry.js';
import AllUsedAppsUnderManagement from './rules/allUsedAppsUnderManagement.js';
import EnforcePermissionPresets from './rules/enforcePermissionPresets.js';
import EnforcePermissionsOnProfileLike from './rules/enforcePermissionsOnProfileLike.js';
import EnforcePermissionsOnUser from './rules/enforcePermissionsOnUser.js';
import NoInactiveUsers from './rules/noInactiveUsers.js';
import NoOtherApexApiLogins from './rules/noOtherApexApiLogins.js';
import NoUserCanSelfAuthorize from './rules/noUserCanSelfAuthorize.js';
import { AuditRunConfig, Policies } from './shape/auditConfigShape.js';
import { PolicyConfig, UserPolicyConfig, UserPrivilegeLevel } from './shape/schema.js';

type PolicyDefinition<T, C extends PolicyConfig = PolicyConfig> = {
  handler: Constructor<T>;
  rules?: RuleHandlerMap;
  configType?: C;
  initialiser?: () => Partial<PolicyConfig>;
};

type PolicyDefinitions = {
  permissionSets: PolicyDefinition<PermissionSetsPolicy>;
  profiles: PolicyDefinition<ProfilesPolicy>;
  users: PolicyDefinition<UsersPolicy, UserPolicyConfig>;
  connectedApps: PolicyDefinition<ConnectedAppsPolicy>;
  settings: PolicyDefinition<SettingsPolicy>;
};

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
    initialiser: () => ({
      options: {
        analyseLastNDaysOfLoginHistory: 30,
        defaultRoleForMissingUsers: UserPrivilegeLevel.STANDARD_USER,
      },
    }),
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
    initialiser: () => ({
      enabled: true,
      rules: {
        EnforceApexSettings: { enabled: true },
        EnforceSecuritySettings: { enabled: true },
        EnforceUserInterfaceSettings: { enabled: true },
        EnforceUserManagementSettings: { enabled: true },
        EnforceConnectedAppSettings: { enabled: true },
      },
    }),
  },
};

export function initPolicyConfig<P extends Policies>(policyName: P): PolicyDefinitions[P]['configType'] {
  const def = PolicyDefinitions[policyName];
  const registry = new RuleRegistry(def.rules);
  const content: PolicyConfig = { enabled: true, rules: {} };
  for (const validRule of registry.registeredRules()) {
    content.rules[validRule] = {
      enabled: true,
    };
  }
  if (def.initialiser) {
    return { ...content, ...def.initialiser() };
  }
  return content;
}

export function loadPolicy<P extends Policies>(
  policyName: P,
  config: AuditRunConfig
): InstanceType<PolicyDefinitions[P]['handler']> {
  const def = PolicyDefinitions[policyName];
  const policyConfig = config.policies[policyName];
  const policy = new def.handler(policyConfig, config, new RuleRegistry(def.rules)) as InstanceType<
    PolicyDefinitions[P]['handler']
  >;
  return policy;
}
