import { Messages } from '@salesforce/core';
import { merge } from '@salesforce/kit';
import { PartialPolicyRuleResult } from '../registry/context.types.js';
import { PolicyRuleViolation, PolicyRuleViolationMute } from '../registry/result.types.js';
import { Policies } from '../registry/definitions.js';
import { LeafNode, RiskTree, TreeNode } from './acceptedRisks.types.js';

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
  private readonly config: RiskTree;

  public constructor(risks?: RiskTree) {
    this.config = {
      users: {
        NoStandardProfilesOnActiveUsers: {
          '*': {
            'Sales Insights Integration User': {
              reason: messages.getMessage('user-skipped-cannot-manage'),
            },
          },
        },
      },
      profiles: {},
      permissionSets: {},
      connectedApps: {},
      settings: {},
    };
    merge(this.config, risks);
  }

  /**
   * Scrubs all accepted risks from the violations of a policy result.
   * The "muted" violations are augmented with the documented reason.
   *
   * @param policyName
   * @param ruleResult
   */
  public scrub(policyName: Policies, ruleResult: PartialPolicyRuleResult): PartialPolicyRuleResult {
    const risks = this.config[policyName]?.[ruleResult.ruleName];
    if (!risks) {
      return ruleResult;
    }
    const { violations, mutedViolations } = scrubViolations(ruleResult.violations, risks);
    return {
      ...ruleResult,
      violations,
      mutedViolations,
    };
  }
}

function isLeaf(node: TreeNode): node is LeafNode {
  return 'reason' in node;
}

/**
 * Traverses the node path and returns the leaf-node or undefined
 * if no LeafNode exists
 *
 * @param node
 * @param path
 * @returns
 */
function traverseRisks(node: TreeNode, ...path: string[]): TreeNode | undefined {
  let current = node;
  for (const key of path) {
    if (isLeaf(current)) {
      // iteration is already one key ahead, so when key = lastElement
      // the current is actually from the second-to-last
      return key === path.at(-2) ? current : undefined;
    }
    if (current[key] && typeof current[key] === 'object') {
      current = current[key];
    } else if (current['*']) {
      current = current['*'];
    }
  }
  return current;
}

function findLeaf(node: TreeNode, ...path: string[]): LeafNode | undefined {
  const maybeLeaf = traverseRisks(node, ...path);
  return maybeLeaf && isLeaf(maybeLeaf) ? maybeLeaf : undefined;
}

function scrubViolations(unscrubbed: PolicyRuleViolation[], acceptedRuleRisks: TreeNode): ViolationsScrubResult {
  const mutedViolations: PolicyRuleViolationMute[] = [];
  const violations: PolicyRuleViolation[] = [];
  for (const violation of unscrubbed) {
    // can we truly iterate all violations per each risk?
    // this is quadratic runtime (O(n2))
    // need to find a smart algorithm that hashes identifiers and only
    // iterates wildcards - linear runtime is MUST
    const riskOrNothing = findLeaf(acceptedRuleRisks, ...violation.identifier);
    if (riskOrNothing) {
      mutedViolations.push({ ...violation, reason: riskOrNothing.reason });
    } else {
      violations.push(violation);
    }
  }
  return { violations, mutedViolations };
}
