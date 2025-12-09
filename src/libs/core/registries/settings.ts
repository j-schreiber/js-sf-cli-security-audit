import z from 'zod';
import { Messages } from '@salesforce/core';
import { AuditRunConfig, RuleMap } from '../file-mgmt/schema.js';
import RuleRegistry, { RegistryRuleResolveResult } from './ruleRegistry.js';
import EnforceSettings from './rules/enforceSettings.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policies.general');

export default class SettingsRuleRegistry extends RuleRegistry {
  public constructor() {
    super({});
  }

  // eslint-disable-next-line class-methods-use-this
  public override resolveRules(ruleObjs: RuleMap, auditContext: AuditRunConfig): RegistryRuleResolveResult {
    const result: RegistryRuleResolveResult = { enabledRules: [], skippedRules: [], resolveErrors: [] };
    Object.entries(ruleObjs).forEach(([ruleName, ruleConfig]) => {
      const settingName = findSettingsName(ruleName);
      if (settingName && ruleConfig.enabled) {
        result.enabledRules.push(
          new EnforceSettings({
            auditContext,
            ruleDisplayName: ruleName,
            settingName,
            ruleConfig: parseRuleConfig(ruleConfig.options),
          })
        );
      } else if (!ruleConfig.enabled) {
        result.skippedRules.push({ name: ruleName, skipReason: messages.getMessage('skip-reason.rule-not-enabled') });
      } else {
        result.resolveErrors.push({
          name: ruleName,
          message: messages.getMessage('resolve-error.no-valid-settings-rule'),
        });
      }
    });
    return result;
  }
}

function parseRuleConfig(ruleConfig?: unknown): z.infer<typeof SettingsRuleConfigSchema> {
  if (ruleConfig) {
    return SettingsRuleConfigSchema.parse(ruleConfig);
  } else {
    return {};
  }
}

export function findSettingsName(ruleName: string): string | null {
  const match = /^Enforce(.+)Settings$/.exec(ruleName);
  return match ? match[1] : null;
}

const SettingsRuleConfigSchema = z.record(z.string(), z.unknown());

export const SettingsRegistry = new SettingsRuleRegistry();
