import { Messages } from '@salesforce/core';
import { PartialPolicyRuleResult, RuleAuditContext } from '../context.types.js';
import { ObjectDefinition } from '../../../../salesforce/index.js';
import PolicyRule, { RuleOptions } from './policyRule.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.objects');

const forbiddenSharingValues: Array<ObjectDefinition['externalSharing']> = [
  'FullAccess',
  'Read',
  'ReadWrite',
  'ReadWriteTransfer',
  'ReadSelect',
];

export default class PrivateExternalAccessForAllObjects extends PolicyRule<ObjectDefinition> {
  public constructor(opts: RuleOptions) {
    super(opts);
  }

  public run(context: RuleAuditContext<ObjectDefinition>): Promise<PartialPolicyRuleResult> {
    const result = this.initResult();
    for (const [objectName, objectDef] of Object.entries(context.resolvedEntities)) {
      if (
        objectDef.type === 'SObject' &&
        objectDef.label &&
        (objectDef.isSharingControllable || (objectDef.isCustom && objectDef.sharingModel === 'Edit'))
      ) {
        if (forbiddenSharingValues.includes(objectDef.externalSharing)) {
          result.violations.push({
            identifier: [objectName],
            message: messages.getMessage('violation.external-sharing-model-not-private', [
              objectDef.label,
              objectDef.externalSharing,
            ]),
          });
        }
      }
    }
    return Promise.resolve(result);
  }
}
