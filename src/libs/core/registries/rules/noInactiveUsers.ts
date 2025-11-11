import { Messages } from '@salesforce/core';
import { NoInactiveUsersOptions, NoInactiveUsersOptionsSchema } from '../../file-mgmt/schema.js';
import { PartialPolicyRuleResult, RuleAuditContext } from '../types.js';
import { differenceInDays } from '../../utils.js';
import { ResolvedUser } from '../users.js';
import PolicyRule, { ConfigurableRuleOptions } from './policyRule.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.users');

export default class NoInactiveUsers extends PolicyRule<ResolvedUser> {
  private ruleConfig: NoInactiveUsersOptions;

  public constructor(localOpts: ConfigurableRuleOptions<NoInactiveUsersOptions>) {
    super(localOpts);
    this.ruleConfig = NoInactiveUsersOptionsSchema.parse(localOpts.ruleConfig ?? {});
  }

  public run(context: RuleAuditContext<ResolvedUser>): Promise<PartialPolicyRuleResult> {
    const result = this.initResult();
    Object.values(context.resolvedEntities).forEach((user) => {
      if (user.lastLogin) {
        const diffInDays = differenceInDays(Date.now(), user.lastLogin);
        if (diffInDays > this.ruleConfig.daysAfterUserIsInactive) {
          result.violations.push({
            identifier: [user.username],
            message: messages.getMessage('violations.inactive-since-n-days', [
              diffInDays,
              new Date(user.lastLogin).toISOString(),
            ]),
          });
        }
      }
    });
    Object.values(context.resolvedEntities).forEach((user) => {
      if (!user.lastLogin) {
        const createdNDaysAgo = differenceInDays(Date.now(), user.createdDate);
        result.violations.push({
          identifier: [user.username],
          message: messages.getMessage('violations.has-never-logged-in', [
            new Date(user.createdDate).toISOString(),
            createdNDaysAgo,
          ]),
        });
      }
    });
    return Promise.resolve(result);
  }
}
