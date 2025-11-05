import { Connection } from '@salesforce/core';
import { AuditPolicyResult, PolicyRuleExecutionResult } from '../result-types.js';
import { Optional } from '../utils.js';
import { ConnectedAppsRegistry } from './connectedApps.js';
import { PermissionSetsRegistry } from './permissionSets.js';
import { ProfilesRegistry } from './profiles.js';
import { UsersRegistry } from './users.js';

export const RuleRegistries = {
  ConnectedApps: ConnectedAppsRegistry,
  Profiles: ProfilesRegistry,
  PermissionSets: PermissionSetsRegistry,
  Users: UsersRegistry,
};

/**
 * A rule must only implement a subset of the rule result. All optional
 * properties are completed by the policy.
 */
export type PartialPolicyRuleResult = Optional<
  PolicyRuleExecutionResult,
  'isCompliant' | 'compliantEntities' | 'violatedEntities'
>;

/**
 *
 */
export type RowLevelPolicyRule<ResolvedEntityType> = {
  run(context: RuleAuditContext<ResolvedEntityType>): Promise<PartialPolicyRuleResult>;
};

export type IPolicy = {
  run(context: AuditContext): Promise<AuditPolicyResult>;
};

export type AuditContext = {
  /**
   * Connection to the target org
   */
  targetOrgConnection: Connection;
};

export type RuleAuditContext<T> = AuditContext & {
  /**
   * Resolved entities from the policy. Can be permission sets,
   * profiles, users, connected apps, etc.
   */
  resolvedEntities: Record<string, T>;
};
