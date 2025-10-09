import { Connection } from '@salesforce/core';
import { PolicyRuleExecutionResult } from '../../audit/types.js';
import PolicySet from '../policySet.js';

export type RowLevelPolicyRule = {
  run(context: RuleExecutionContext): Promise<PolicyRuleExecutionResult>;
};

export type RuleExecutionContext = {
  /**
   * Connection to the target org
   */
  targetOrgConnection: Connection;

  /**
   * The complete and initialised audit config for this run. Use this
   * to access classifications, other policies, etc.
   */
  auditConfig: PolicySet;
};
