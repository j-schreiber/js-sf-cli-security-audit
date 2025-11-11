import { Messages } from '@salesforce/core';
import MDAPI from '../mdapi/mdapiRetriever.js';
import { AuditRunConfig, PermissionSetLikeMap, PermSetsPolicyFileContent } from '../file-mgmt/schema.js';
import { AuditContext } from '../registries/types.js';
import { ProfilesRiskPreset } from '../policy-types.js';
import { EntityResolveError } from '../result-types.js';
import { PermissionSetsRegistry, ResolvedPermissionSet } from '../registries/permissionSets.js';
import Policy, { getTotal, ResolveEntityResult } from './policy.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policies.general');

export default class PermissionSetPolicy extends Policy<ResolvedPermissionSet> {
  private totalEntities: number;
  public constructor(
    public config: PermSetsPolicyFileContent,
    public auditContext: AuditRunConfig,
    registry = PermissionSetsRegistry
  ) {
    super(config, auditContext, registry);
    this.totalEntities = this.config.permissionSets ? Object.keys(this.config.permissionSets).length : 0;
  }

  protected async resolveEntities(context: AuditContext): Promise<ResolveEntityResult<ResolvedPermissionSet>> {
    this.emit('entityresolve', {
      total: this.totalEntities,
      resolved: 0,
    });
    const successfullyResolved: Record<string, ResolvedPermissionSet> = {};
    const unresolved: Record<string, EntityResolveError> = {};
    const retriever = new MDAPI(context.targetOrgConnection);
    const resolvedPermsets = await retriever.resolve(
      'PermissionSet',
      filterCategorizedPermsets(this.config.permissionSets)
    );
    Object.entries(this.config.permissionSets).forEach(([key, val]) => {
      const resolved = resolvedPermsets[key];
      if (resolved) {
        successfullyResolved[key] = {
          metadata: resolved,
          preset: this.config.permissionSets[key].preset,
          name: key,
        };
      } else if (successfullyResolved[key] === undefined) {
        if (val.preset === ProfilesRiskPreset.UNKNOWN) {
          unresolved[key] = { name: key, message: messages.getMessage('preset-unknown', ['Permission Set']) };
        } else {
          unresolved[key] = { name: key, message: messages.getMessage('entity-not-found') };
        }
      }
    });
    const result = { resolvedEntities: successfullyResolved, ignoredEntities: Object.values(unresolved) };
    this.emit('entityresolve', {
      total: this.totalEntities,
      resolved: getTotal(result),
    });
    return result;
  }
}

function filterCategorizedPermsets(permSets: PermissionSetLikeMap): string[] {
  const filteredNames: string[] = [];
  Object.entries(permSets).forEach(([key, val]) => {
    if (val.preset !== ProfilesRiskPreset.UNKNOWN) {
      filteredNames.push(key);
    }
  });
  return filteredNames;
}
