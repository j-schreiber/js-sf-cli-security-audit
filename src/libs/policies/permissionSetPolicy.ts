import { Messages } from '@salesforce/core';
import { PermissionSet } from '@jsforce/jsforce-node/lib/api/metadata.js';
import MdapiRetriever from '../mdapiRetriever.js';
import PermSetsRuleRegistry from '../config/registries/permissionSets.js';
import { AuditRunConfig, PermissionSetLikeMap, PermSetsPolicyFileContent } from '../config/audit-run/schema.js';
import RuleRegistry from '../config/registries/ruleRegistry.js';
import { EntityResolveError } from '../audit/types.js';
import { AuditContext } from './interfaces/policyRuleInterfaces.js';
import Policy, { getTotal, ResolveEntityResult } from './policy.js';
import { PermissionRiskLevelPresets } from './types.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policies.general');

export type ResolvedPermissionSet = {
  name: string;
  preset: string;
  metadata: PermissionSet;
};
export default class PermissionSetPolicy extends Policy {
  private totalEntities: number;
  public constructor(
    public config: PermSetsPolicyFileContent,
    public auditContext: AuditRunConfig,
    registry: RuleRegistry = new PermSetsRuleRegistry()
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
        if (val.preset === PermissionRiskLevelPresets.UNKNOWN) {
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
    if (val.preset !== PermissionRiskLevelPresets.UNKNOWN) {
      filteredNames.push(key);
    }
  });
  return filteredNames;
}
