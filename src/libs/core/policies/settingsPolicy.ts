import { Messages } from '@salesforce/core';
import { AuditRunConfig, BasePolicyFileContent, RuleMap } from '../file-mgmt/schema.js';
import { findSettingsName, SettingsRegistry } from '../registries/settings.js';
import { MDAPI, SalesforceSetting } from '../../../salesforce/index.js';
import { AuditContext } from '../registries/types.js';
import { EntityResolveError } from '../result-types.js';
import EnforceSettings from '../registries/rules/enforceSettings.js';
import Policy, { ResolveEntityResult } from './policy.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policies.general');

export default class SettingsPolicy extends Policy<SalesforceSetting> {
  public constructor(
    public config: BasePolicyFileContent,
    public auditConfig: AuditRunConfig,
    registry = SettingsRegistry
  ) {
    super(config, auditConfig, registry);
  }

  protected async resolveEntities(context: AuditContext): Promise<ResolveEntityResult<SalesforceSetting>> {
    const numberOfRules = Object.keys(this.config.rules).length;
    this.emit('entityresolve', {
      total: numberOfRules,
      resolved: 0,
    });
    const settingNames = extractSettingNames(this.config.rules);
    const settingsRetriever = MDAPI.create(context.targetOrgConnection);
    const actuallyResolvedSettings = await settingsRetriever.resolve('Settings', settingNames);
    this.removeInvalidSettingsFromResolvedRules(actuallyResolvedSettings);
    this.emit('entityresolve', {
      total: numberOfRules,
      resolved: actuallyResolvedSettings.size,
    });
    return {
      resolvedEntities: actuallyResolvedSettings,
      ignoredEntities: findIgnoredEntities(actuallyResolvedSettings, this.config.rules),
    };
  }

  private removeInvalidSettingsFromResolvedRules(validSettings: Record<string, SalesforceSetting>): void {
    this.resolvedRules.enabledRules.forEach((rule, index) => {
      if (isEnforceSettingsRule(rule)) {
        if (!validSettings[rule.settingName]) {
          this.resolvedRules.enabledRules.splice(index, 1);
          this.resolvedRules.skippedRules.push({
            name: rule.ruleDisplayName,
            skipReason: messages.getMessage('skip-reason.failed-to-resolve-setting', [rule.settingName]),
          });
        }
      }
    });
  }
}

function isEnforceSettingsRule(cls: unknown): cls is EnforceSettings {
  return (cls as EnforceSettings).ruleDisplayName !== undefined;
}

function findIgnoredEntities(settingsMap: Record<string, SalesforceSetting>, rules: RuleMap): EntityResolveError[] {
  const result = new Array<EntityResolveError>();
  for (const ruleName of Object.keys(rules)) {
    const maybeName = findSettingsName(ruleName);
    if (!maybeName) {
      continue;
    }
    if (!settingsMap[maybeName]) {
      result.push({ name: maybeName, message: messages.getMessage('resolve-error.failed-to-resolve-setting') });
    }
  }
  return result;
}

function extractSettingNames(rules: RuleMap): string[] {
  const names = [];
  for (const ruleName of Object.keys(rules)) {
    const maybeName = findSettingsName(ruleName);
    if (maybeName) {
      names.push(maybeName);
    }
  }
  return names;
}
