import { AuditPolicyResult, PolicyEntityResolveError, PolicyRuleExecutionResult } from '../audit/types.js';
import AuditRunConfig from './interfaces/auditRunConfig.js';
import { AuditContext, IPolicy, RowLevelPolicyRule } from './interfaces/policyRuleInterfaces.js';

export type ResolveEntityResult = {
  resolvedEntities: Record<string, unknown>;
  ignoredEntities: PolicyEntityResolveError[];
};
export default abstract class Policy implements IPolicy {
  public constructor(public auditContext: AuditRunConfig, protected rules: RowLevelPolicyRule[]) {}

  /**
   * Runs all rules of a policy
   *
   * @param context
   * @returns
   */
  public async run(context: AuditContext): Promise<AuditPolicyResult> {
    const resolveResult = await this.resolveEntities(context);
    const ruleResultPromises = Array<Promise<PolicyRuleExecutionResult>>();
    for (const rule of this.rules) {
      ruleResultPromises.push(rule.run({ ...context, resolvedEntities: resolveResult.resolvedEntities }));
    }
    const ruleResults = await Promise.all(ruleResultPromises);
    const executedRules: Record<string, PolicyRuleExecutionResult> = {};
    for (const ruleResult of ruleResults) {
      executedRules[ruleResult.ruleName] = ruleResult;
      ruleResult.isCompliant = ruleResult.violations.length === 0;
    }
    return {
      isCompliant: isCompliant(executedRules),
      enabled: true,
      executedRules,
      skippedRules: [],
      auditedEntities: Object.keys(resolveResult.resolvedEntities),
      ignoredEntities: resolveResult.ignoredEntities,
    };
  }

  protected abstract resolveEntities(context: AuditContext): Promise<ResolveEntityResult>;
}

function isCompliant(ruleResults: Record<string, PolicyRuleExecutionResult>): boolean {
  const list = Object.values(ruleResults);
  return list.reduce((prevVal, currentVal) => prevVal && currentVal.isCompliant, list[0].isCompliant);
}
