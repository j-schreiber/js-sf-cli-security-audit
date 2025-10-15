import { Messages } from '@salesforce/core';
import { PolicyRuleExecutionResult } from '../../audit/types.js';
import { ResolvedConnectedApp } from '../connectedAppPolicy.js';
import { RuleAuditContext } from '../interfaces/policyRuleInterfaces.js';
import PolicyRule, { RuleOptions } from './policyRule.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.connectedApps');

export default class AllUsedAppsUnderManagement extends PolicyRule {
  public constructor(opts: RuleOptions) {
    super(opts);
  }

  public run(context: RuleAuditContext): Promise<PolicyRuleExecutionResult> {
    const result = this.initResult();
    const resolvedConnectedApps = context.resolvedEntities as Record<string, ResolvedConnectedApp>;
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
