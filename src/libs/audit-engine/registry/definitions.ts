import { AuditConfigShapeDefinition, ExtractAuditConfigTypes } from '../file-manager/fileManager.types.js';
import ConnectedAppsPolicy from './policies/connectedApps.js';
import PermissionSetsPolicy from './policies/permissionSets.js';
import ProfilesPolicy from './policies/profiles.js';
import SettingsPolicy from './policies/settings.js';
import UsersPolicy from './policies/users.js';
import RuleRegistry, { RuleHandlerMap, Constructor } from './ruleRegistry.js';
import AllUsedAppsUnderManagement from './rules/allUsedAppsUnderManagement.js';
import EnforceLoginIpRanges from './rules/enforceLoginIpRanges.js';
import EnforcePermissionPresets from './rules/enforcePermissionPresets.js';
import EnforcePermissionsOnProfileLike from './rules/enforcePermissionsOnProfileLike.js';
import EnforcePermissionsOnUser from './rules/enforcePermissionsOnUser.js';
import NoInactiveUsers from './rules/noInactiveUsers.js';
import NoOtherApexApiLogins from './rules/noOtherApexApiLogins.js';
import NoStandardProfilesOnActiveUsers from './rules/noStandardProfilesOnActiveUsers.js';
import NoUserCanSelfAuthorize from './rules/noUserCanSelfAuthorize.js';
import { BaseAuditConfigShape } from './shape/auditConfigShape.js';
import { AcceptedRisksSchema, PolicyConfig, UserPolicyConfig } from './shape/schema.js';

type PolicyDefinition<T, C extends PolicyConfig = PolicyConfig> = {
  handler: Constructor<T>;
  rules?: RuleHandlerMap;
  configType?: C;
};

type PolicyDefinitions = {
  permissionSets: PolicyDefinition<PermissionSetsPolicy>;
  profiles: PolicyDefinition<ProfilesPolicy>;
  users: PolicyDefinition<UsersPolicy, UserPolicyConfig>;
  connectedApps: PolicyDefinition<ConnectedAppsPolicy>;
  settings: PolicyDefinition<SettingsPolicy>;
};

export type AuditRunConfig = ExtractAuditConfigTypes<typeof AuditConfigShape>;
export type Policies = keyof AuditRunConfig['policies'];
export type PolicyShapes = AuditRunConfig['policies'];
export type Classifications = keyof AuditRunConfig['classifications'];
export type ClassificationShapes = AuditRunConfig['classifications'];

/**
 * Central definition of policies (handlers + registered rules).
 * These definitions are used to load policies and derive config
 * for accepted risks.
 */
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
      EnforceLoginIpRanges,
    },
  },
  users: {
    handler: UsersPolicy,
    rules: {
      NoOtherApexApiLogins,
      NoInactiveUsers,
      EnforcePermissionClassifications: EnforcePermissionsOnUser,
      EnforcePermissionPresets,
      NoStandardProfilesOnActiveUsers,
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

/**
 * Merges the base audit config shape with a dynamically generated shape
 * for all accepted risks. Automatically generates a correlating config
 * for each registered rule in the PolicyDefinitions.
 */
export const AuditConfigShape = {
  ...BaseAuditConfigShape,
  acceptedRisks: {
    dirs: Object.fromEntries(
      Object.entries(PolicyDefinitions).map(([policyName, policyDef]) => [
        policyName,
        {
          files: policyDef.rules
            ? Object.fromEntries(
                Object.entries(policyDef.rules).map(([policyRule]) => [policyRule, { schema: AcceptedRisksSchema }])
              )
            : {},
        },
      ])
    ),
  },
} satisfies AuditConfigShapeDefinition;

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
