import { Messages } from '@salesforce/core';
import { NoInactiveUsersOptions } from '../../file-mgmt/schema.js';
import { PartialPolicyRuleResult, RuleAuditContext } from '../types.js';
import { differenceInDays } from '../../utils.js';
import { ResolvedUser } from '../users.js';
import PolicyRule, { ConfigurableRuleOptions } from './policyRule.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.users');

export default class NoInactiveUsers extends PolicyRule<ResolvedUser> {
  public constructor(private localOpts: ConfigurableRuleOptions<NoInactiveUsersOptions>) {
    super(localOpts);
  }

  public run(context: RuleAuditContext<ResolvedUser>): Promise<PartialPolicyRuleResult> {
    const result = this.initResult();
    Object.values(context.resolvedEntities).forEach((user) => {
      const loginDates: number[] = [];
      user.logins.forEach((loginSummary) => {
        loginDates.push(loginSummary.lastLogin);
      });
      if (loginDates.length >= 1) {
        const actualLastLogin = Math.max(...loginDates);
        const diffInDays = differenceInDays(Date.now(), actualLastLogin);
        if (diffInDays > this.localOpts.ruleConfig.daysAfterUserIsInactive) {
          result.violations.push({
            identifier: [user.username],
            message: messages.getMessage('violations.inactive-since-n-days', [
              diffInDays,
              new Date(actualLastLogin).toISOString(),
            ]),
          });
        }
      }
    });
    return Promise.resolve(result);
  }
}
