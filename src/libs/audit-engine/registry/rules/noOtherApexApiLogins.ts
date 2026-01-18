import { Messages } from '@salesforce/core';
import { PartialPolicyRuleResult, RuleAuditContext } from '../context.types.js';
import { ResolvedUser } from '../policies/users.js';
import PolicyRule, { RuleOptions } from './policyRule.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.users');

export default class NoOtherApexApiLogins extends PolicyRule<ResolvedUser> {
  public constructor(opts: RuleOptions) {
    super(opts);
  }

  public run(context: RuleAuditContext<ResolvedUser>): Promise<PartialPolicyRuleResult> {
    const result = this.initResult();
    for (const user of Object.values(context.resolvedEntities)) {
      if (!user.logins) {
        continue;
      }
      for (const loginSummary of user.logins) {
        if (loginSummary.loginType === 'Other Apex API') {
          result.violations.push({
            identifier: [user.username, new Date(loginSummary.lastLogin).toISOString()],
            message: messages.getMessage('violations.no-other-apex-api-logins', [
              loginSummary.loginCount,
              this.opts.auditConfig.policies.users?.options.analyseLastNDaysOfLoginHistory,
            ]),
          });
        }
      }
    }
    return Promise.resolve(result);
  }
}
