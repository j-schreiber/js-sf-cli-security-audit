import { Messages } from '@salesforce/core';
import {
  PolicyRuleExecutionResult,
  PolicyRuleViolation,
  PolicyRuleViolationMute,
  RuleComponentMessage,
} from '../../audit/types.js';
import { RowLevelPolicyRule, RuleAuditContext } from '../interfaces/policyRuleInterfaces.js';
import AuditRunConfig from '../interfaces/auditRunConfig.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);

export type RuleOptions = {
  auditContext: AuditRunConfig;
  ruleDisplayName: string;
};

export default abstract class PolicyRule implements RowLevelPolicyRule {
  public auditContext: AuditRunConfig;
  public ruleDisplayName: string;

  public constructor(opts: RuleOptions) {
    this.auditContext = opts.auditContext;
    this.ruleDisplayName = opts.ruleDisplayName;
  }

  protected initResult(): PolicyRuleExecutionResult {
    return {
      ruleName: this.ruleDisplayName,
      isCompliant: true,
      violations: new Array<PolicyRuleViolation>(),
      mutedViolations: new Array<PolicyRuleViolationMute>(),
      warnings: new Array<RuleComponentMessage>(),
      errors: new Array<RuleComponentMessage>(),
    };
  }

  public abstract run(context: RuleAuditContext): Promise<PolicyRuleExecutionResult>;
}
