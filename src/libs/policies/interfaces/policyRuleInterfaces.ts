import { Connection } from '@salesforce/core';
import { AuditPolicyResult, PolicyRuleExecutionResult } from '../../audit/types.js';

export type RowLevelPolicyRule = {
  run(context: AuditContext): Promise<PolicyRuleExecutionResult>;
};

export type Policy = {
  run(context: AuditContext): Promise<AuditPolicyResult>;
};

export type AuditContext = {
  /**
   * Connection to the target org
   */
  targetOrgConnection: Connection;
};
