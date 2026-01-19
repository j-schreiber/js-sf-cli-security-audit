import { Messages } from '@salesforce/core';
import { PartialPolicyRuleResult, RuleAuditContext } from '../context.types.js';
import { SalesforceSetting } from '../policies/settings.js';
import PolicyRule, { ConfigurableRuleOptions } from './policyRule.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.settings');

type EnforceSettingsOpts = ConfigurableRuleOptions<Record<string, unknown>> & {
  settingName: string;
};

export default class EnforceSettings extends PolicyRule<unknown> {
  public settingName;

  public constructor(private readonly ruleOptions: EnforceSettingsOpts) {
    super(ruleOptions);
    this.settingName = this.ruleOptions.settingName;
  }

  public run(context: RuleAuditContext<SalesforceSetting>): Promise<PartialPolicyRuleResult> {
    const result = this.initResult();
    const settingContent = context.resolvedEntities[this.ruleOptions.settingName];
    const rootIdentifier = `${this.ruleOptions.settingName}Settings`;
    checkSettings(this.ruleOptions.ruleConfig, result, [rootIdentifier], settingContent);
    if (result.violations.length === 0) {
      result.compliantEntities = [rootIdentifier];
      result.violatedEntities = [];
    } else {
      result.compliantEntities = [];
      result.violatedEntities = [`${this.ruleOptions.settingName}Settings`];
    }
    return Promise.resolve(result);
  }
}

function checkSettings(
  expectedValues: SalesforceSetting,
  resultSoFar: PartialPolicyRuleResult,
  pathSoFar: string[],
  actualValues?: SalesforceSetting
): void {
  for (const [settingsKey, expectedValue] of Object.entries(expectedValues)) {
    const settingsPath = [...pathSoFar, settingsKey];
    if (!actualValues || actualValues[settingsKey] === undefined) {
      resultSoFar.warnings.push({
        identifier: settingsPath,
        message: messages.getMessage('warnings.property-does-not-exist'),
      });
      continue;
    }
    if (typeof expectedValue === 'object' && actualValues) {
      checkSettings(
        expectedValue as SalesforceSetting,
        resultSoFar,
        settingsPath,
        actualValues[settingsKey] as SalesforceSetting
      );
    } else if (
      typeof expectedValue === 'string' ||
      typeof expectedValue === 'boolean' ||
      typeof expectedValue === 'number'
    ) {
      if (expectedValue !== actualValues[settingsKey]) {
        resultSoFar.violations.push({
          identifier: settingsPath,
          message: messages.getMessage('violations.expected-value-does-not-match', [
            expectedValue,
            String(actualValues[settingsKey]),
          ]),
        });
      }
    }
  }
}
