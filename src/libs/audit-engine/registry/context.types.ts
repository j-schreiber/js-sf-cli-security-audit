import { Connection } from '@salesforce/core';
import { Optional } from '../../../utils.js';
import AcceptedRisks from '../accepted-risks/acceptedRisks.js';
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
 * Map of partial results for executed rules
 */
export type PartialRuleResults = Record<string, PartialPolicyRuleResult>;

/**
 *
 */
export type RowLevelPolicyRule<ResolvedEntityType> = {
  run(context: RuleAuditContext<ResolvedEntityType>): Promise<PartialPolicyRuleResult>;
};

export type IPolicy = {
  executeRules(context: AuditContext): Promise<PartialRuleResults>;
  finalise(partialResults: PartialRuleResults, riskManager: AcceptedRisks): AuditPolicyResult;
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
