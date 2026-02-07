import { Messages } from '@salesforce/core';
import { PolicyRuleViolation, PolicyRuleViolationMute, RuleComponentMessage } from '../result.types.js';
import { PartialPolicyRuleResult, RowLevelPolicyRule, RuleAuditContext } from '../context.types.js';
import { AuditRunConfig } from '../definitions.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);

export type RuleOptions = {
  auditConfig: AuditRunConfig;
  ruleDisplayName: string;
};

export type ConfigurableRuleOptions<T> = RuleOptions & {
  ruleConfig: T;
};

export default abstract class PolicyRule<EntityType> implements RowLevelPolicyRule<EntityType> {
  public auditConfig: AuditRunConfig;
  public ruleDisplayName: string;

  public constructor(protected opts: RuleOptions) {
    this.auditConfig = opts.auditConfig;
    this.ruleDisplayName = opts.ruleDisplayName;
  }

  protected initResult(): PartialPolicyRuleResult {
    return {
      ruleName: this.ruleDisplayName,
      violations: new Array<PolicyRuleViolation>(),
      mutedViolations: new Array<PolicyRuleViolationMute>(),
      warnings: new Array<RuleComponentMessage>(),
      errors: new Array<RuleComponentMessage>(),
    };
  }

  public abstract run(context: RuleAuditContext<EntityType>): Promise<PartialPolicyRuleResult>;
}
