import EventEmitter from 'node:events';
import AcceptedRisks from '../accepted-risks/acceptedRisks.js';
import RuleRegistry, { RegistryRuleResolveResult } from './ruleRegistry.js';
import { AuditPolicyResult, EntityResolveError, PolicyRuleExecutionResult } from './result.types.js';
import {
  AuditContext,
  IPolicy,
  PartialPolicyRuleResult,
  PartialRuleResults,
  RowLevelPolicyRule,
} from './context.types.js';
import { PolicyConfig } from './shape/schema.js';
import { AuditRunConfig, Policies } from './definitions.js';

export type ResolveEntityResult<T> = {
  resolvedEntities: Record<string, T>;
  ignoredEntities: EntityResolveError[];
};

export default abstract class Policy<T> extends EventEmitter implements IPolicy {
  protected resolvedRules: RegistryRuleResolveResult;
  protected entities?: ResolveEntityResult<T>;

  public constructor(
    protected policyName: Policies,
    public config: PolicyConfig,
    public auditConfig: AuditRunConfig,
    protected registry: RuleRegistry
  ) {
    super();
    this.resolvedRules = registry.resolveRules(config.rules, auditConfig);
  }

  public getExecutableRules(): Array<RowLevelPolicyRule<T>> {
    return this.resolvedRules.enabledRules;
  }

  /**
   * Resolves all entities of the policy.
   */
  public async resolve(context: AuditContext): Promise<ResolveEntityResult<T>> {
    // when a policy is disabled, we still want to appear it in audit results
    // as disabled with 0 resolved entities and 0 executed rules
    if (!this.config.enabled) {
      this.entities = { resolvedEntities: {}, ignoredEntities: [] };
    }
    this.entities ??= await this.resolveEntities(context);
    return this.entities;
  }

  /**
   * Executes all rules of a policy and returns the partial rule results.
   *
   * @param context
   */
  public async executeRules(context: AuditContext): Promise<PartialRuleResults> {
    if (!this.config.enabled) {
      return {};
    }
    const resolveResult = await this.resolve(context);
    const ruleResultPromises = new Array<Promise<PartialPolicyRuleResult>>();
    for (const rule of this.resolvedRules.enabledRules) {
      ruleResultPromises.push(rule.run({ ...context, resolvedEntities: resolveResult.resolvedEntities }));
    }
    const results: PartialRuleResults = {};
    const promises = await Promise.all(ruleResultPromises);
    for (const result of promises) {
      results[result.ruleName] = result;
    }
    return results;
  }

  /**
   * Finalises the partial rule results. Scrubs violations from accepted risks,
   * adds compliant and violated entities, and completes summaries.
   *
   * @param partialResults
   * @param riskManager Instance of global risk manager
   */
  public finalise(partialResults: PartialRuleResults, riskManager: AcceptedRisks): AuditPolicyResult {
    const resolveResult = this.entities!;
    const executedRules: Record<string, PolicyRuleExecutionResult> = {};
    for (const ruleResult of Object.values(partialResults)) {
      const scrubbedResult = riskManager.scrub(this.policyName, ruleResult);
      const { compliantEntities, violatedEntities } = evalResolvedEntities<T>(scrubbedResult, resolveResult);
      executedRules[scrubbedResult.ruleName] = {
        ...scrubbedResult,
        isCompliant: scrubbedResult.violations.length === 0,
        compliantEntities,
        violatedEntities,
      };
    }
    return {
      isCompliant: isCompliant(executedRules),
      enabled: this.config.enabled,
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
  return {
    compliantEntities: ruleResult.compliantEntities ?? compliantEntities,
    violatedEntities: ruleResult.violatedEntities ?? Array.from(violatedEntities),
  };
}

// TODO: Can be removed when policy emit their resolve result
// and we propagate this as an aggregated resolve status
export function getTotal(resolveResult: ResolveEntityResult<unknown>): number {
  const resolvedCount = resolveResult.resolvedEntities ? Object.keys(resolveResult.resolvedEntities).length : 0;
  const ignoredCount = resolveResult.ignoredEntities ? resolveResult.ignoredEntities.length : 0;
  return resolvedCount + ignoredCount;
}
