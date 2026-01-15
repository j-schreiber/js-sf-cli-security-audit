import { Messages } from '@salesforce/core';
import { AuditRunConfig, BasePolicyFileContent, PermissionSetsMap } from '../file-mgmt/schema.js';
import { AuditContext } from '../registries/types.js';
import { UserPrivilegeLevel } from '../policy-types.js';
import { EntityResolveError } from '../result-types.js';
import { PermissionSet, PermissionSets } from '../../../salesforce/index.js';
import { PermissionSetsRegistry } from '../registries/permissionSets.js';
import Policy, { ResolveEntityResult } from './policy.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policies.general');

export type ClassifiedPermissionSet = PermissionSet & {
  role: UserPrivilegeLevel;
};

export default class PermissionSetPolicy extends Policy<ClassifiedPermissionSet> {
  private totalEntities: number;
  private readonly classifications: PermissionSetsMap;

  public constructor(
    public config: BasePolicyFileContent,
    public auditContext: AuditRunConfig,
    registry = PermissionSetsRegistry
  ) {
    super(config, auditContext, registry);
    this.classifications = this.auditConfig.classifications.permissionSets?.content.permissionSets ?? {};
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
