import z from 'zod';
import { Messages } from '@salesforce/core';
import { PartialPolicyRuleResult, RuleAuditContext } from '../context.types.js';
import { differenceInDays } from '../../../../utils.js';
import { ResolvedUser } from '../policies/users.js';
import { throwAsSfError } from '../schema.js';
import PolicyRule, { ConfigurableRuleOptions } from './policyRule.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.users');

const NoInactiveUsersOptionsSchema = z.strictObject({
  daysAfterUserIsInactive: z.number().default(90),
});

type NoInactiveUsersOptions = z.infer<typeof NoInactiveUsersOptionsSchema>;

export default class NoInactiveUsers extends PolicyRule<ResolvedUser> {
  private readonly ruleConfig;

  public constructor(localOpts: ConfigurableRuleOptions<NoInactiveUsersOptions>) {
    super(localOpts);
    this.ruleConfig = parseRuleOptions(localOpts.ruleConfig);
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

function parseRuleOptions(anyObject?: unknown): NoInactiveUsersOptions {
  const parseResult = NoInactiveUsersOptionsSchema.safeParse(anyObject ?? {});
  if (parseResult.success) {
    return parseResult.data;
  } else {
    throwAsSfError('users.yml', parseResult.error, ['rules', 'NoInactiveUsers', 'options']);
  }
}
