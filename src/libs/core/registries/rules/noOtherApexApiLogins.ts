import { Messages } from '@salesforce/core';
import { PartialPolicyRuleResult, RuleAuditContext } from '../types.js';
import { ResolvedUser } from '../users.js';
import PolicyRule, { RuleOptions } from './policyRule.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.users');

export default class NoOtherApexApiLogins extends PolicyRule<ResolvedUser> {
  public constructor(opts: RuleOptions) {
    super(opts);
  }

  public run(context: RuleAuditContext<ResolvedUser>): Promise<PartialPolicyRuleResult> {
    const result = this.initResult();
    Object.values(context.resolvedEntities).forEach((user) => {
      user.logins.forEach((loginSummary) => {
        if (loginSummary.loginType === 'Other Apex API') {
          result.violations.push({
            identifier: [user.username],
            message: messages.getMessage('violations.no-other-apex-api-logins', [loginSummary.loginCount]),
          });
        }
      });
    });
    return Promise.resolve(result);
  }
}
