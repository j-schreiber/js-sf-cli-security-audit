import { Messages } from '@salesforce/core';
import { AuditRunConfig } from './definitions.js';
import { EntityResolveError, PolicyRuleSkipResult } from './result.types.js';
import { RowLevelPolicyRule } from './context.types.js';
import { PolicyConfig } from './shape/schema.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policies.general');

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Constructor<T, Args extends any[] = any[]> = new (...args: Args) => T;

export type RuleHandlerMap = Record<string, Constructor<RowLevelPolicyRule<unknown>>>;

/**
 * Result contains the actually available and enabled rules
 * from the raw config file. Rules that are not present in the
 * policie's registry are errors, disabled rules are skipped.
 */
export type RegistryRuleResolveResult = {
  enabledRules: Array<RowLevelPolicyRule<unknown>>;
  skippedRules: PolicyRuleSkipResult[];
  resolveErrors: EntityResolveError[];
};

/**
 * The rule registry holds all available rules for a given policy at run time.
 * It is designed to be extendible so we can easily register new rules and it will
 * allow users to BYOR ("bring your own rules").
 */
export default class RuleRegistry {
  private availableRules;

  public constructor(rules?: RuleHandlerMap) {
    this.availableRules = rules ?? {};
  }

  /**
   * Returns the display/config names of all registered rules
   *
   * @returns
   */
  public registeredRules(): string[] {
    return Object.keys(this.availableRules);
  }

  /**
   * Resolves a given set of rule configs to actually registered rules. Unknown
   * rules are ignored and disabled rules are skipped.
   *
   * @param ruleObjs
   * @param auditConfig
   * @returns
   */
  public resolveRules(ruleObjs: PolicyConfig['rules'], auditConfig: AuditRunConfig): RegistryRuleResolveResult {
    const enabledRules = new Array<RowLevelPolicyRule<unknown>>();
    const skippedRules = new Array<PolicyRuleSkipResult>();
    const resolveErrors = new Array<EntityResolveError>();
    Object.entries(ruleObjs).forEach(([ruleName, ruleConfig]) => {
      if (this.availableRules[ruleName] && ruleConfig.enabled) {
        enabledRules.push(
          new this.availableRules[ruleName]({ auditConfig, ruleDisplayName: ruleName, ruleConfig: ruleConfig.options })
        );
      } else if (ruleConfig.enabled === false) {
        skippedRules.push({ name: ruleName, skipReason: messages.getMessage('skip-reason.rule-not-enabled') });
      } else {
        resolveErrors.push({ name: ruleName, message: messages.getMessage('resolve-error.rule-not-registered') });
      }
    });
    return { enabledRules, skippedRules, resolveErrors };
  }
}
