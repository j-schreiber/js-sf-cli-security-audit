import { Messages } from '@salesforce/core';
import { isEmpty } from '@salesforce/kit';
import { PermissionSet } from '@jsforce/jsforce-node/lib/api/metadata.js';
import MdapiRetriever from '../mdapiRetriever.js';
import { PolicyEntityResolveError } from '../audit/types.js';
import { AuditContext, RowLevelPolicyRule } from './interfaces/policyRuleInterfaces.js';
import { PermissionSetLikeMap, PermSetsPolicyFileContent, PolicyRuleConfig } from './schema.js';
import AuditRunConfig from './interfaces/auditRunConfig.js';
import Policy, { ResolveEntityResult } from './policy.js';
import { PermissionRiskLevelPresets } from './types.js';
import EnforceUserPermsClassificationOnPermSets from './rules/enforceUserPermsClassificationOnPermSets.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policies.general');

export type ResolvedPermissionSet = {
  name: string;
  preset: string;
  metadata: PermissionSet;
};
export default class PermissionSetPolicy extends Policy {
  public constructor(public config: PermSetsPolicyFileContent, public auditContext: AuditRunConfig) {
    super(auditContext, resolveRules(auditContext, config.rules));
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

function resolveRules(
  auditContext: AuditRunConfig,
  ruleConfigs?: Record<string, PolicyRuleConfig>
): RowLevelPolicyRule[] {
  if (isEmpty(ruleConfigs)) {
    return [];
  }
  const resolved = new Array<RowLevelPolicyRule>();
  // need to rewrite to Object.entries when I need ruleConfig
  for (const ruleName of Object.keys(ruleConfigs!)) {
    switch (ruleName) {
      case 'EnforceUserPermissionClassifications':
        resolved.push(new EnforceUserPermsClassificationOnPermSets(auditContext));
        break;
      default:
        break;
    }
  }
  return resolved;
}
