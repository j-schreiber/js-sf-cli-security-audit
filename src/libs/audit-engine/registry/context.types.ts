import { Connection } from '@salesforce/core';
import { Optional } from '../../../utils.js';
import { AuditPolicyResult, PolicyRuleExecutionResult } from './result.types.js';

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

/**
 * Run-time context of execution, that is directly resolved
 * from the target org.
 */
export type RuleAuditContext<T> = AuditContext & {
  /**
   * Resolved entities from the policy. Can be permission sets,
   * profiles, users, connected apps, etc.
   */
  resolvedEntities: Record<string, T>;
};
