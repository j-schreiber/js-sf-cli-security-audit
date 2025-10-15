import { Connection } from '@salesforce/core';
import { AuditPolicyResult, PolicyRuleExecutionResult } from '../../audit/types.js';

export type RowLevelPolicyRule = {
  run(context: RuleAuditContext): Promise<PolicyRuleExecutionResult>;
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
