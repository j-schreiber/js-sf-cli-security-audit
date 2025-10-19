import { Connection } from '@salesforce/core';
import { AuditPolicyResult, PolicyRuleExecutionResult } from '../../audit/types.js';
import { Optional } from '../../utils.js';

/**
 * A rule must only implement a subset of the rule result. All optional
 * properties are completed by the policy.
 */
export type PartialPolicyRuleResult = Optional<
  PolicyRuleExecutionResult,
  'isCompliant' | 'compliantEntities' | 'violatedEntities'
>;

export type RowLevelPolicyRule = {
  run(context: RuleAuditContext): Promise<PartialPolicyRuleResult>;
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

export type RuleAuditContext = AuditContext & {
  /**
   * Resolved entities from the policy. Can be permission sets,
   * profiles, users, connected apps, etc.
   */
  resolvedEntities: Record<string, unknown>;
};
