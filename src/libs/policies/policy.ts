import EventEmitter from 'node:events';
import { AuditPolicyResult, EntityResolveError, PolicyRuleExecutionResult } from '../core/result-types.js';
import { AuditRunConfig, BasePolicyFileContent } from '../core/file-mgmt/schema.js';
import RuleRegistry, { RegistryRuleResolveResult } from '../core/registries/ruleRegistry.js';
import { AuditContext, IPolicy, PartialPolicyRuleResult } from '../core/registries/types.js';

export type ResolveEntityResult<T> = {
  resolvedEntities: Record<string, T>;
  ignoredEntities: EntityResolveError[];
};
export default abstract class Policy<T> extends EventEmitter implements IPolicy {
  protected resolvedRules: RegistryRuleResolveResult;
  protected entities?: ResolveEntityResult<T>;

  public constructor(
    public config: BasePolicyFileContent,
    public auditConfig: AuditRunConfig,
    protected registry: RuleRegistry
  ) {
    super();
    this.resolvedRules = registry.resolveRules(config.rules, auditConfig);
  }

  /**
   * Resolves all entities of the policy.
   */
  public async resolve(context: AuditContext): Promise<ResolveEntityResult<T>> {
    if (!this.entities) {
      this.entities = await this.resolveEntities(context);
    }
    return this.entities;
  }

  /**
   * Runs all rules of a policy. If the entities are not yet resolved, they are
   * resolved on the fly before rules are executed.
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
    const resolveResult = await this.resolve(context);
    const ruleResultPromises = Array<Promise<PartialPolicyRuleResult>>();
    for (const rule of this.resolvedRules.enabledRules) {
      ruleResultPromises.push(rule.run({ ...context, resolvedEntities: resolveResult.resolvedEntities }));
    }
    const ruleResults = await Promise.all(ruleResultPromises);
    const executedRules: Record<string, PolicyRuleExecutionResult> = {};
    for (const ruleResult of ruleResults) {
      const { compliantEntities, violatedEntities } = evalResolvedEntities<T>(ruleResult, resolveResult);
      executedRules[ruleResult.ruleName] = {
        ...ruleResult,
        isCompliant: ruleResult.violations.length === 0,
        compliantEntities,
        violatedEntities,
      };
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

  protected abstract resolveEntities(context: AuditContext): Promise<ResolveEntityResult<T>>;
}

function isCompliant(ruleResults: Record<string, PolicyRuleExecutionResult>): boolean {
  const list = Object.values(ruleResults);
  if (list.length === 0) {
    return true;
  }
  return list.reduce((prevVal, currentVal) => prevVal && currentVal.isCompliant, list[0].isCompliant);
}

function evalResolvedEntities<T>(
  ruleResult: PartialPolicyRuleResult,
  entities: ResolveEntityResult<T>
): { compliantEntities: string[]; violatedEntities: string[] } {
  const compliantEntities: string[] = [];
  const violatedEntities = new Set<string>();
  ruleResult.violations.forEach((vio) => {
    if (vio.identifier.length > 0) {
      violatedEntities.add(vio.identifier[0]);
    }
  });
  Object.keys(entities.resolvedEntities).forEach((entityIdentifier) => {
    if (!violatedEntities.has(entityIdentifier)) {
      compliantEntities.push(entityIdentifier);
    }
  });
  return { compliantEntities, violatedEntities: Array.from(violatedEntities) };
}

export function getTotal(resolveResult: ResolveEntityResult<unknown>): number {
  const resolvedCount = resolveResult.resolvedEntities ? Object.keys(resolveResult.resolvedEntities).length : 0;
  const ignoredCount = resolveResult.ignoredEntities ? resolveResult.ignoredEntities.length : 0;
  return resolvedCount + ignoredCount;
}
