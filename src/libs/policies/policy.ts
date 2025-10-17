import { AuditPolicyResult, EntityResolveError, PolicyRuleExecutionResult } from '../audit/types.js';
import RuleRegistry from '../config/registries/ruleRegistry.js';
import { RegistryRuleResolveResult } from '../config/registries/types.js';
import AuditRunConfig from './interfaces/auditRunConfig.js';
import { AuditContext, IPolicy } from './interfaces/policyRuleInterfaces.js';
import { BasePolicyFileContent } from './schema.js';

export type ResolveEntityResult = {
  resolvedEntities: Record<string, unknown>;
  ignoredEntities: EntityResolveError[];
};
export default abstract class Policy implements IPolicy {
  protected resolvedRules: RegistryRuleResolveResult;

  public constructor(
    public auditContext: AuditRunConfig,
    public config: BasePolicyFileContent,
    protected registry: RuleRegistry
  ) {
    this.resolvedRules = registry.resolveRules(config.rules, auditContext);
  }

  /**
   * Runs all rules of a policy
   *
   * @param context
   * @returns
   */
  public async run(context: AuditContext): Promise<AuditPolicyResult> {
    if (!this.config.enabled) {
      return {
        isCompliant: true,
        enabled: false,
        executedRules: {},
        skippedRules: [],
        auditedEntities: [],
        ignoredEntities: [],
      };
    }
    const resolveResult = await this.resolveEntities(context);
    const ruleResultPromises = Array<Promise<PolicyRuleExecutionResult>>();
    for (const rule of this.resolvedRules.enabledRules) {
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
      skippedRules: this.resolvedRules.skippedRules,
      auditedEntities: Object.keys(resolveResult.resolvedEntities),
      ignoredEntities: resolveResult.ignoredEntities,
    };
  }

  protected abstract resolveEntities(context: AuditContext): Promise<ResolveEntityResult>;
}

function isCompliant(ruleResults: Record<string, PolicyRuleExecutionResult>): boolean {
  const list = Object.values(ruleResults);
  if (list.length === 0) {
    return true;
  }
  return list.reduce((prevVal, currentVal) => prevVal && currentVal.isCompliant, list[0].isCompliant);
}
