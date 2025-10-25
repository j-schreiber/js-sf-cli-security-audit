import { Messages } from '@salesforce/core';
import MdapiRetriever from '../core/mdapi/mdapiRetriever.js';
import { AuditRunConfig, PermissionSetLikeMap, PermSetsPolicyFileContent } from '../core/file-mgmt/schema.js';
import { AuditContext, RuleRegistries } from '../core/registries/types.js';
import { ProfilesRiskPreset } from '../core/policy-types.js';
import { EntityResolveError } from '../core/result-types.js';
import { ResolvedPermissionSet } from '../core/registries/permissionSets.js';
import Policy, { getTotal, ResolveEntityResult } from './policy.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policies.general');

export default class PermissionSetPolicy extends Policy {
  private totalEntities: number;
  public constructor(
    public config: PermSetsPolicyFileContent,
    public auditContext: AuditRunConfig,
    registry = RuleRegistries.PermissionSets
  ) {
    super(config, auditContext, registry);
    this.totalEntities = this.config.permissionSets ? Object.keys(this.config.permissionSets).length : 0;
  }

  protected async resolveEntities(context: AuditContext): Promise<ResolveEntityResult> {
    this.emit('entityresolve', {
      total: this.totalEntities,
      resolved: 0,
    });
    const successfullyResolved: Record<string, ResolvedPermissionSet> = {};
    const unresolved: Record<string, EntityResolveError> = {};
    const retriever = new MdapiRetriever(context.targetOrgConnection);
    const resolvedPermsets = await retriever.retrievePermissionsets(
      filterCategorizedPermsets(this.config.permissionSets)
    );
    Object.entries(resolvedPermsets).forEach(([permsetName, resolvedPermset]) => {
      successfullyResolved[permsetName] = {
        metadata: resolvedPermset,
        preset: this.config.permissionSets[permsetName].preset,
        name: permsetName,
      };
    });
    Object.entries(this.config.permissionSets).forEach(([key, val]) => {
      if (successfullyResolved[key] === undefined) {
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
