import z from 'zod';
import { Messages } from '@salesforce/core';
import { PartialPolicyRuleResult, RuleAuditContext } from '../context.types.js';
import { ResolvedUser } from '../policies/users.js';
import PolicyRule, { RuleOptions } from './policyRule.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.users');

const NoOtherApexApiLoginsOptionsSchema = z.strictObject({
  includeAllLoginAttempts: z.boolean().default(true),
});

export default class NoOtherApexApiLogins extends PolicyRule<ResolvedUser> {
  private readonly options;

  public constructor(opts: RuleOptions) {
    super(opts);
    this.options = this.parseOptions(NoOtherApexApiLoginsOptionsSchema, opts.ruleConfig, 'users.yml');
  }

  public run(context: RuleAuditContext<ResolvedUser>): Promise<PartialPolicyRuleResult> {
    const result = this.initResult();
    for (const user of Object.values(context.resolvedEntities)) {
      if (!user.logins) {
        continue;
      }
      const logins = filterLoginAggregate(this.options.includeAllLoginAttempts, user.logins);
      for (const loginSummary of logins) {
        result.violations.push({
          identifier: [user.username, new Date(loginSummary.lastLogin).toISOString()],
          message: messages.getMessage(
            loginSummary.includesAttempts
              ? 'violations.no-attempted-other-apex-api-logins'
              : 'violations.no-successful-other-apex-api-logins',
            [loginSummary.loginCount, this.opts.auditConfig.policies.users?.options.analyseLastNDaysOfLoginHistory]
          ),
        });
      }
    }
    return Promise.resolve(result);
  }
}

function filterLoginAggregate(includeAll: boolean, userLogins: ResolvedUser['logins']): LoginSummaryAggregate[] {
  if (!userLogins) {
    return [];
  }
  const apexApiLogins = userLogins.filter((login) => login.loginType === 'Other Apex API');
  const filteredLogins = includeAll ? apexApiLogins : apexApiLogins.filter((login) => login.status === 'Success');
  const map = filteredLogins.reduce((acc, login) => {
    const key = `${login.loginType}::${login.application}`;
    const existing = acc.get(key);

    if (existing) {
      existing.loginCount += login.loginCount;
      existing.lastLogin = Math.max(existing.lastLogin, login.lastLogin);
      existing.includesAttempts = existing.includesAttempts || login.status !== 'Success';
    } else {
      acc.set(key, {
        loginCount: login.loginCount,
        lastLogin: login.lastLogin,
        includesAttempts: login.status !== 'Success',
      });
    }

    return acc;
  }, new Map<string, LoginSummaryAggregate>());

  return Array.from(map.values());
}

type LoginSummaryAggregate = {
  lastLogin: number;
  loginCount: number;
  includesAttempts: boolean;
};
