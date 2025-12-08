import { Messages } from '@salesforce/core';
import { AuditRunConfig, BasePolicyFileContent } from '../file-mgmt/schema.js';
import { SettingsRegistry } from '../registries/settings.js';
import Policy, { ResolveEntityResult } from './policy.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);

export default class SettingsPolicy extends Policy<unknown> {
  public constructor(
    public config: BasePolicyFileContent,
    public auditConfig: AuditRunConfig,
    registry = SettingsRegistry
  ) {
    super(config, auditConfig, registry);
  }

  protected async resolveEntities(): Promise<ResolveEntityResult<unknown>> {
    const numberOfRules = Object.keys(this.config.rules).length;
    this.emit('entityresolve', {
      total: numberOfRules,
      resolved: numberOfRules,
    });
    return Promise.resolve({ resolvedEntities: {}, ignoredEntities: [] });
  }
}
