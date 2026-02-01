import z from 'zod';
import { Messages } from '@salesforce/core';
import RuleRegistry, { RegistryRuleResolveResult } from '../ruleRegistry.js';
import EnforceSettings from '../rules/enforceSettings.js';
import { MDAPI, MdapiRegistry } from '../../../../salesforce/index.js';
import Policy, { ResolveEntityResult } from '../policy.js';
import { AuditContext } from '../context.types.js';
import { EntityResolveError } from '../result.types.js';
import { AuditRunConfig } from '../shape/auditConfigShape.js';
import { PolicyConfig } from '../shape/schema.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policies.general');

export type SalesforceSetting = Awaited<ReturnType<MdapiRegistry['namedTypes']['Settings']['resolve']>>['string'];

export class SettingsRuleRegistry extends RuleRegistry {
  public constructor() {
    super({});
  }

  // eslint-disable-next-line class-methods-use-this
  public override resolveRules(
    ruleObjs: PolicyConfig['rules'],
    auditContext: AuditRunConfig
  ): RegistryRuleResolveResult {
    const result: RegistryRuleResolveResult = { enabledRules: [], skippedRules: [], resolveErrors: [] };
    Object.entries(ruleObjs).forEach(([ruleName, ruleConfig]) => {
      const settingName = findSettingsName(ruleName);
      if (settingName && ruleConfig.enabled) {
        result.enabledRules.push(
          new EnforceSettings({
            auditConfig: auditContext,
            ruleDisplayName: ruleName,
            settingName,
            ruleConfig: SettingsRuleConfigSchema.parse(ruleConfig.options ?? {}),
          })
        );
      } else if (!ruleConfig.enabled) {
        result.skippedRules.push({ name: ruleName, skipReason: messages.getMessage('skip-reason.rule-not-enabled') });
      } else {
        result.skippedRules.push({
          name: ruleName,
          skipReason: messages.getMessage('resolve-error.no-valid-settings-rule'),
        });
      }
    });
    return result;
  }
}

/**
 * Settings policy derives its entities from the rules it has configured. Rules and
 * entities directly correlate. If a rule is skipped, the corresponding entity is ignored.
 */
export default class SettingsPolicy extends Policy<SalesforceSetting> {
  public constructor(public config: PolicyConfig, public auditConfig: AuditRunConfig) {
    super('settings', config, auditConfig, new SettingsRuleRegistry());
  }

  protected async resolveEntities(context: AuditContext): Promise<ResolveEntityResult<SalesforceSetting>> {
    const legitSettings = getSettingsFromEnabledRules(this.config.rules);
    this.emit('entityresolve', {
      total: legitSettings.length,
      resolved: 0,
    });
    const settingsRetriever = MDAPI.create(context.targetOrgConnection);
    const actuallyResolvedSettings = await settingsRetriever.resolve('Settings', legitSettings);
    this.removeInvalidSettingsFromResolvedRules(actuallyResolvedSettings);
    this.emit('entityresolve', {
      total: legitSettings.length,
      resolved: Object.keys(actuallyResolvedSettings).length,
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

function getSettingsFromEnabledRules(rules: PolicyConfig['rules']): string[] {
  const settings = [];
  for (const [ruleName, ruleConfig] of Object.entries(rules)) {
    const maybeSettingName = findSettingsName(ruleName);
    if (maybeSettingName && ruleConfig.enabled) {
      settings.push(maybeSettingName);
    }
  }
  return settings;
}

function isEnforceSettingsRule(cls: unknown): cls is EnforceSettings {
  return (cls as EnforceSettings).ruleDisplayName !== undefined;
}

function findIgnoredEntities(
  settingsMap: Record<string, SalesforceSetting>,
  rules: PolicyConfig['rules']
): EntityResolveError[] {
  const result = new Array<EntityResolveError>();
  for (const ruleName of Object.keys(rules)) {
    const maybeName = findSettingsName(ruleName);
    if (!maybeName) {
      continue;
    }
    if (!rules[ruleName].enabled) {
      result.push({ name: maybeName, message: messages.getMessage('skip-reason.rule-not-enabled') });
      continue;
    }
    if (!settingsMap[maybeName]) {
      result.push({ name: maybeName, message: messages.getMessage('resolve-error.failed-to-resolve-setting') });
    }
  }
  return result;
}

function findSettingsName(ruleName: string): string | null {
  const match = /^Enforce(.+)Settings$/.exec(ruleName);
  return match ? match[1] : null;
}

const SettingsRuleConfigSchema = z.record(z.string(), z.unknown());
