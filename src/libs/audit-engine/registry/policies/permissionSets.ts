import { Messages } from '@salesforce/core';
import { PermissionSet, PermissionSets } from '../../../../salesforce/index.js';
import Policy, { ResolveEntityResult } from '../policy.js';
import { EntityResolveError } from '../result.types.js';
import RuleRegistry from '../ruleRegistry.js';
import { AuditContext } from '../context.types.js';
import { AuditRunConfig } from '../shape/auditConfigShape.js';
import { PermissionSetClassifications, PolicyConfig, UserPrivilegeLevel } from '../shape/schema.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policies.general');

export type ClassifiedPermissionSet = PermissionSet & {
  role: UserPrivilegeLevel;
};

export default class PermissionSetsPolicy extends Policy<ClassifiedPermissionSet> {
  private totalEntities: number;
  private readonly classifications: PermissionSetClassifications;

  public constructor(public config: PolicyConfig, public auditConfig: AuditRunConfig, registry: RuleRegistry) {
    super(config, auditConfig, registry);
    this.classifications = this.auditConfig.classifications.permissionSets?.permissionSets ?? {};
    this.totalEntities = Object.keys(this.classifications).length;
  }

  protected async resolveEntities(context: AuditContext): Promise<ResolveEntityResult<ClassifiedPermissionSet>> {
    const permsetsRepo = new PermissionSets(context.targetOrgConnection);
    permsetsRepo.addListener('entityresolve', (statusEvt) => this.emit('entityresolve', statusEvt));
    const allPermsets = await permsetsRepo.resolve();
    const ignoredEntities = this.buildIgnoredEntities(allPermsets);
    const classifiedPermsets = Object.keys(this.classifications).filter(
      (permsetName) => ignoredEntities[permsetName] === undefined
    );
    this.totalEntities = Object.keys(ignoredEntities).length + classifiedPermsets.length;
    this.emit('entityresolve', {
      total: this.totalEntities,
      resolved: 0,
    });
    const resolvedPermsets = await permsetsRepo.resolve({ withMetadata: true, filterNames: classifiedPermsets });
    const resolvedEntities: Record<string, ClassifiedPermissionSet> = {};
    for (const permsetName of classifiedPermsets) {
      const metadata = resolvedPermsets.get(permsetName);
      if (metadata) {
        resolvedEntities[permsetName] = {
          ...metadata,
          role: this.classifications[permsetName].role,
        };
      } else {
        ignoredEntities[permsetName] = {
          name: permsetName,
          message: messages.getMessage('permission-set-invalid-no-metadata'),
        };
      }
    }
    this.emit('entityresolve', {
      total: this.totalEntities,
      resolved: this.totalEntities,
    });
    return { resolvedEntities, ignoredEntities: Object.values(ignoredEntities) };
  }

  private buildIgnoredEntities(allPermsets: Map<string, PermissionSet>): Record<string, EntityResolveError> {
    const ignoredEntities: Record<string, EntityResolveError> = {};
    for (const [permsetName, permsetDef] of Object.entries(this.classifications)) {
      if (permsetDef.role === UserPrivilegeLevel.UNKNOWN) {
        ignoredEntities[permsetName] = {
          name: permsetName,
          message: messages.getMessage('preset-unknown', ['Permission Set']),
        };
      } else if (!allPermsets.has(permsetName)) {
        ignoredEntities[permsetName] = {
          name: permsetName,
          message: messages.getMessage('entity-not-found'),
        };
      }
    }
    for (const permset of allPermsets.values()) {
      if (this.classifications[permset.name] === undefined) {
        ignoredEntities[permset.name] = {
          name: permset.name,
          message: messages.getMessage('entity-not-classified'),
        };
      }
    }
    return ignoredEntities;
  }
}
