import { Messages } from '@salesforce/core';
import { EntityResolveError, PolicyRuleSkipResult } from '../../audit/types.js';
import { AuditRunConfig, RuleMap } from '../audit-run/schema.js';
import { RowLevelPolicyRule } from '../../policies/interfaces/policyRuleInterfaces.js';
import { RegistryRuleResolveResult } from './types.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policies.general');

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
   * rules are ignored and disabled rules are skipped.
   *
   * @param ruleObjs
   * @param auditContext
   * @returns
   */
  public resolveRules(ruleObjs: RuleMap, auditContext: AuditRunConfig): RegistryRuleResolveResult {
    const enabledRules = new Array<RowLevelPolicyRule>();
    const skippedRules = new Array<PolicyRuleSkipResult>();
    const resolveErrors = new Array<EntityResolveError>();
    Object.entries(ruleObjs).forEach(([ruleName, ruleConfig]) => {
      if (this.rules[ruleName] && ruleConfig.enabled) {
        enabledRules.push(
          new this.rules[ruleName]({ auditContext, ruleDisplayName: ruleName, ruleConfig: ruleConfig.config })
        );
      } else if (!ruleConfig.enabled) {
        skippedRules.push({ name: ruleName, skipReason: messages.getMessage('skip-reason.rule-not-enabled') });
      } else {
        resolveErrors.push({ name: ruleName, message: messages.getMessage('resolve-error.rule-not-registered') });
      }
    });
    return { enabledRules, skippedRules, resolveErrors };
  }
}
