import AuditRunConfig from '../../policies/interfaces/auditRunConfig.js';
import { RowLevelPolicyRule } from '../../policies/interfaces/policyRuleInterfaces.js';
import { RuleMap } from '../../policies/schema.js';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Constructor<T, Args extends any[] = any[]> = new (...args: Args) => T;

/**
 * The rule registry holds all available rules for a given policy at run time.
 * It is designed to be extendible so we can easily register new rules and it will
 * allow users to BYOR ("bring your own rules").
 */
export default class RuleRegistry {
  public constructor(public rules: Record<string, Constructor<RowLevelPolicyRule>>) {}

  /**
   * Returns the display/config names of all registered rules
   *
   * @returns
   */
  public registeredRules(): string[] {
    return Object.keys(this.rules);
  }

  /**
   * Resolves a given set of rule configs to actually registered rules. Unknown
   * rules are ignored.
   *
   * @param ruleObjs
   * @param auditContext
   * @returns
   */
  public resolveEnabledRules(ruleObjs: RuleMap, auditContext: AuditRunConfig): RowLevelPolicyRule[] {
    if (ruleObjs) {
      const result = new Array<RowLevelPolicyRule>();
      Object.entries(ruleObjs).forEach(([ruleName, ruleConfig]) => {
        if (this.rules[ruleName] && ruleConfig.enabled) {
          result.push(
            new this.rules[ruleName]({ auditContext, ruleDisplayName: ruleName, ruleConfig: ruleConfig.config })
          );
        }
      });
      return result;
    }
    return [];
  }
}
