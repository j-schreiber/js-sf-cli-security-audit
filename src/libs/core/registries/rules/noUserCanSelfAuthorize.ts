import { Messages } from '@salesforce/core';
import { PartialPolicyRuleResult, RuleAuditContext } from '../types.js';
import { ConnectedApp } from '../../../../salesforce/index.js';
import PolicyRule, { RuleOptions } from './policyRule.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.connectedApps');

export default class NoUserCanSelfAuthorize extends PolicyRule<ConnectedApp> {
  public constructor(opts: RuleOptions) {
    super(opts);
  }

  public run(context: RuleAuditContext<ConnectedApp>): Promise<PartialPolicyRuleResult> {
    const result = this.initResult();
    const resolvedConnectedApps = context.resolvedEntities;
    Object.values(resolvedConnectedApps).forEach((app) => {
      if (!app.onlyAdminApprovedUsersAllowed) {
        if (app.overrideByApiSecurityAccess) {
          result.warnings.push({
            identifier: [app.name],
            message: messages.getMessage('warnings.users-can-self-authorize-but-setting-overrides'),
          });
        } else {
          result.violations.push({
            identifier: [app.name],
            message: messages.getMessage('violations.users-can-self-authorize'),
          });
        }
      }
    });
    return Promise.resolve(result);
  }
}
