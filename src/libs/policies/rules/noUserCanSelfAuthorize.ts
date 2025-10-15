import { Messages } from '@salesforce/core';
import { PolicyRuleExecutionResult } from '../../audit/types.js';
import { RuleAuditContext } from '../interfaces/policyRuleInterfaces.js';
import { ResolvedConnectedApp } from '../connectedAppPolicy.js';
import PolicyRule, { RuleOptions } from './policyRule.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.connectedApps');

export default class NoUserCanSelfAuthorize extends PolicyRule {
  public constructor(opts: RuleOptions) {
    super(opts);
  }

  public run(context: RuleAuditContext): Promise<PolicyRuleExecutionResult> {
    const result = this.initResult();
    const resolvedConnectedApps = context.resolvedEntities as Record<string, ResolvedConnectedApp>;
    Object.values(resolvedConnectedApps).forEach((app) => {
      if (app.usersCanSelfAuthorize) {
        result.violations.push({
          identifier: [app.name],
          message: messages.getMessage('violations.users-can-self-authorize'),
        });
      }
    });
    return Promise.resolve(result);
  }
}
