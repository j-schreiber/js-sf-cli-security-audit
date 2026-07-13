import { Messages } from '@salesforce/core';
import { PartialPolicyRuleResult, RuleAuditContext } from '../context.types.js';
import { ObjectDefinition } from '../../../../salesforce/index.js';
import PolicyRule, { RuleOptions } from './policyRule.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.objects');

const allowedSharingValues: Array<ObjectDefinition['externalSharing']> = ['Private', 'ControlledByParent'] as const;

export default class PrivateExternalAccessForAllObjects extends PolicyRule<ObjectDefinition> {
  public constructor(opts: RuleOptions) {
    super(opts);
  }

  public run(context: RuleAuditContext<ObjectDefinition>): Promise<PartialPolicyRuleResult> {
    const result = this.initResult();
    const ruleRelevantObjects = Object.values(context.resolvedEntities).filter(
      (objectDef) =>
        objectDef.type === 'SObject' &&
        objectDef.label &&
        (objectDef.isSharingControllable || (objectDef.isCustom && objectDef.sharingModel === 'Edit'))
    );
    // did not find a way to reliably determine the sobjects that are actually shareable/configurable
    // even SF apparently does not know: View canvas shows 190 objects, edit canvas only 130.
    // the idea is to first filter the objects that are actually configurable, then only iterate
    // on the objects and evaluate the externalSharing prop.
    const cleanedFalsePositives = ruleRelevantObjects.filter((objectDef) => objectDef.internalSharing !== 'Private');
    for (const objectDef of cleanedFalsePositives) {
      if (!allowedSharingValues.includes(objectDef.externalSharing)) {
        result.violations.push({
          identifier: [objectDef.developerName],
          message: messages.getMessage('violation.external-sharing-model-not-private', [
            objectDef.label,
            objectDef.externalSharing,
          ]),
        });
      }
    }
    return Promise.resolve(result);
  }
}
