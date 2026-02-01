import { Messages } from '@salesforce/core';
import { PartialPolicyRuleResult, RuleAuditContext } from '../context.types.js';
import { ResolvedUser } from '../policies/users.js';
import PolicyRule, { RuleOptions } from './policyRule.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.users');

export default class NoStandardProfilesOnActiveUsers extends PolicyRule<ResolvedUser> {
  public constructor(opts: RuleOptions) {
    super(opts);
  }

  public run(context: RuleAuditContext<ResolvedUser>): Promise<PartialPolicyRuleResult> {
    const result = this.initResult();
    for (const user of Object.values(context.resolvedEntities)) {
      if (!user.profileMetadata) {
        continue;
      }
      if (!user.profileMetadata.custom && user.isActive) {
        result.violations.push({
          identifier: [user.username, user.profileName],
          message: messages.getMessage('violations.active-user-has-standard-profile'),
        });
      } else if (!user.isActive && !user.profileMetadata.custom) {
        result.warnings.push({
          identifier: [user.username, user.profileName],
          message: messages.getMessage('violations.inactive-user-has-standard-profile'),
        });
      }
    }
    return Promise.resolve(result);
  }
}
