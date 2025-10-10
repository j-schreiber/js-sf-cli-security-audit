import { AuditPolicyResult, PolicyRuleExecutionResult } from '../audit/types.js';
import AuditRunConfig from './interfaces/auditRunConfig.js';
import { AuditContext, IPolicy, RowLevelPolicyRule } from './interfaces/policyRuleInterfaces.js';

export default class Policy implements IPolicy {
  protected rules: RowLevelPolicyRule[] = [];

  public constructor(public auditContext: AuditRunConfig) {}

  /**
   * Runs all rules of a policy
   *
   * @param context
   * @returns
   */
  public async run(context: AuditContext): Promise<AuditPolicyResult> {
    const ruleResultPromises = Array<Promise<PolicyRuleExecutionResult>>();
    for (const rule of this.rules) {
      ruleResultPromises.push(rule.run(context));
    }
    const ruleResults = await Promise.all(ruleResultPromises);
    const executedRules: Record<string, PolicyRuleExecutionResult> = {};
    ruleResults.forEach((rr) => (executedRules[rr.ruleName] = rr));
    return { isCompliant: true, enabled: true, executedRules, skippedRules: [] };
  }
}
