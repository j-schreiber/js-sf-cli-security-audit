import { Messages } from '@salesforce/core';
import { PartialPolicyRuleResult } from '../registry/context.types.js';
import { PolicyRuleViolation, PolicyRuleViolationMute } from '../registry/result.types.js';
import { Policies } from '../registry/shape/auditConfigShape.js';
import { AcceptedRisksConfig, AcceptedRuleRisks } from './acceptedRisks.types.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'acceptedRisks');

type ViolationsScrubResult = {
  violations: PolicyRuleViolation[];
  mutedViolations: PolicyRuleViolationMute[];
};

/**
 * Post-processing for violations from an audit run. Filters violations
 * where identifier matches one of the documented accept risks pattern
 * and mutes them.
 */
export default class AcceptedRisks {
  private readonly config: AcceptedRisksConfig;

  public constructor() {
    this.config = {
      users: {
        NoStandardProfilesOnActiveUsers: [
          {
            identifierMatcher: ['*', 'Sales Insights Integration User'],
            reason: messages.getMessage('user-skipped-cannot-manage'),
          },
        ],
      },
      profiles: {},
      permissionSets: {},
      connectedApps: {},
      settings: {},
    };
  }

  /**
   * Scrubs a policy result from all accepted risks
   *
   * @param policyName
   * @param ruleResult
   */
  public scrub(policyName: Policies, ruleResult: PartialPolicyRuleResult): PartialPolicyRuleResult {
    const ruleConfig = this.config[policyName][ruleResult.ruleName];
    if (!ruleConfig || ruleConfig.length === 0) {
      return ruleResult;
    }
    const { violations, mutedViolations } = scrubViolations(ruleResult.violations, ruleConfig);
    return {
      ...ruleResult,
      violations,
      mutedViolations,
    };
  }
}

function scrubViolations(violations: PolicyRuleViolation[], acceptedRisks: AcceptedRuleRisks[]): ViolationsScrubResult {
  const mutedViolations: PolicyRuleViolationMute[] = [];
  for (const risk of acceptedRisks) {
    // can we truly iterate all violations per each risk?
    // this is quadratic runtime (O(n2))
    // need to find a smart algorithm that hashes identifiers and only
    // iterates wildcards - linear runtime is MUST
    violations.forEach((violation, index) => {
      if (matches(violation.identifier, risk.identifierMatcher)) {
        mutedViolations.push({ ...violation, reason: risk.reason });
        violations.splice(index, 1);
      }
    });
  }
  return { violations, mutedViolations };
}

function matches(identifier: string[], identifierMatcher: string[]): boolean {
  return identifier.length === 2 && identifier[1] === identifierMatcher[1];
}
