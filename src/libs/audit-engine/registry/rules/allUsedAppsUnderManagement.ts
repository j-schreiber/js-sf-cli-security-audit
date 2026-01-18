import { Messages } from '@salesforce/core';
import { PartialPolicyRuleResult, RuleAuditContext } from '../context.types.js';
import { ConnectedApp } from '../../../../salesforce/index.js';
import PolicyRule, { RuleOptions } from './policyRule.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.connectedApps');

export default class AllUsedAppsUnderManagement extends PolicyRule<ConnectedApp> {
  public constructor(opts: RuleOptions) {
    super(opts);
  }

  public run(context: RuleAuditContext<ConnectedApp>): Promise<PartialPolicyRuleResult> {
    const result = this.initResult();
    const resolvedConnectedApps = context.resolvedEntities;
    Object.values(resolvedConnectedApps).forEach((app) => {
      if (app.origin === 'OauthToken') {
        result.violations.push({
          identifier: [app.name],
          message: messages.getMessage('violations.app-used-but-not-registered', [app.users.length, app.useCount]),
        });
      }
    });
    return Promise.resolve(result);
  }
}
