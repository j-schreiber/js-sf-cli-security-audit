import { Messages } from '@salesforce/core';
import z from 'zod';
import { PolicyRuleViolation, PolicyRuleViolationMute, RuleComponentMessage } from '../../result-types.js';
import { PartialPolicyRuleResult, RowLevelPolicyRule, RuleAuditContext } from '../types.js';
import { AuditRunConfig, throwAsSfError } from '../../file-mgmt/schema.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);

export type RuleOptions = {
  auditContext: AuditRunConfig;
  ruleDisplayName: string;
};

export type ConfigurableRuleOptions<T> = RuleOptions & {
  ruleConfig: T;
};

export default abstract class PolicyRule<EntityType> implements RowLevelPolicyRule<EntityType> {
  public auditContext: AuditRunConfig;
  public ruleDisplayName: string;

  public constructor(protected opts: RuleOptions) {
    this.auditContext = opts.auditContext;
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

export function parseRuleOptions(
  policyName: string,
  rulePath: string[],
  schema: z.ZodObject,
  anyObject?: unknown
): z.infer<typeof schema> {
  const parseResult = schema.safeParse(anyObject ?? {});
  if (parseResult.success) {
    return parseResult.data;
  } else {
    throwAsSfError(policyName, parseResult.error, [...rulePath, 'options']);
  }
}
