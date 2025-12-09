import { Messages } from '@salesforce/core';
import { AuditRunConfig, BasePolicyFileContent, RuleMap } from '../file-mgmt/schema.js';
import { findSettingsName, SettingsRegistry } from '../registries/settings.js';
import AnySettingsMetadata, { SalesforceSetting } from '../mdapi/anySettingsMetadata.js';
import { AuditContext } from '../registries/types.js';
import { EntityResolveError } from '../result-types.js';
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
    const settingsRetriever = new AnySettingsMetadata(context.targetOrgConnection);
    const actuallyResolvedSettings = await settingsRetriever.resolve(settingNames);
    this.emit('entityresolve', {
      total: numberOfRules,
      resolved: actuallyResolvedSettings.size,
    });
    return Promise.resolve({
      resolvedEntities: convertToRecord(actuallyResolvedSettings),
      ignoredEntities: findIgnoredEntities(actuallyResolvedSettings, this.config.rules),
    });
  }
}

function convertToRecord(settingsMap: Map<string, SalesforceSetting>): Record<string, SalesforceSetting> {
  const result: Record<string, SalesforceSetting> = {};
  for (const [settingsName, settingsValue] of settingsMap.entries()) {
    result[settingsName] = settingsValue;
  }
  return result;
}

function findIgnoredEntities(settingsMap: Map<string, SalesforceSetting>, rules: RuleMap): EntityResolveError[] {
  const result = new Array<EntityResolveError>();
  for (const ruleName of Object.keys(rules)) {
    const maybeName = findSettingsName(ruleName);
    if (!maybeName) {
      result.push({ name: ruleName, message: messages.getMessage('resolve-error.no-valid-settings-rule') });
      continue;
    }
    if (!settingsMap.has(maybeName) || !settingsMap.get(maybeName)) {
      result.push({ name: maybeName, message: messages.getMessage('resolve-error.failed-to-resolve-setting') });
      continue;
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
