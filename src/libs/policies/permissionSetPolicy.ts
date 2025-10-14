import { Messages } from '@salesforce/core';
import { PermissionSet } from '@jsforce/jsforce-node/lib/api/metadata.js';
import MdapiRetriever from '../mdapiRetriever.js';
import PermSetsRuleRegistry from '../config/registries/permissionSets.js';
import RuleRegistry from '../config/registries/ruleRegistry.js';
import { PolicyEntityResolveError } from '../audit/types.js';
import { AuditContext } from './interfaces/policyRuleInterfaces.js';
import { PermissionSetLikeMap, PermSetsPolicyFileContent } from './schema.js';
import AuditRunConfig from './interfaces/auditRunConfig.js';
import Policy, { ResolveEntityResult } from './policy.js';
import { PermissionRiskLevelPresets } from './types.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policies.general');

export type ResolvedPermissionSet = {
  name: string;
  preset: string;
  metadata: PermissionSet;
};
export default class PermissionSetPolicy extends Policy {
  public constructor(
    public config: PermSetsPolicyFileContent,
    public auditContext: AuditRunConfig,
    registry: RuleRegistry = new PermSetsRuleRegistry()
  ) {
    super(auditContext, registry.resolveEnabledRules(config.rules, auditContext));
  }

  protected async resolveEntities(context: AuditContext): Promise<ResolveEntityResult> {
    const successfullyResolved: Record<string, ResolvedPermissionSet> = {};
    const unresolved: Record<string, PolicyEntityResolveError> = {};
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
    return { resolvedEntities: successfullyResolved, ignoredEntities: Object.values(unresolved) };
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
