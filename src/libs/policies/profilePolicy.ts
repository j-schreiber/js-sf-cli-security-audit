import { isEmpty } from '@salesforce/kit';
import { QueryResult } from '@jsforce/jsforce-node';
import { Messages } from '@salesforce/core';
import { Profile as ProfileMetadata } from '@jsforce/jsforce-node/lib/api/metadata.js';
import { PolicyEntityResolveError } from '../audit/types.js';
import { AuditContext, RowLevelPolicyRule } from './interfaces/policyRuleInterfaces.js';
import { PolicyRuleConfig, ProfilesPolicyFileContent } from './schema.js';
import AuditRunConfig from './interfaces/auditRunConfig.js';
import Policy, { ResolveEntityResult } from './policy.js';
import { Profile } from './salesforceStandardTypes.js';
import { PermissionRiskLevelPresets } from './types.js';
import EnforceUserPermsClassificationOnProfiles from './rules/enforceUserPermsClassificationOnProfiles.js';
import EnforceCustomPermsClassificationOnProfiles from './rules/enforceCustomPermsClassificationOnProfiles.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policies.general');

export type ResolvedProfile = {
  name: string;
  preset: string;
  metadata: ProfileMetadata;
};

export default class ProfilePolicy extends Policy {
  public constructor(public config: ProfilesPolicyFileContent, public auditContext: AuditRunConfig) {
    super(auditContext, resolveRules(auditContext, config.rules));
  }

  protected async resolveEntities(context: AuditContext): Promise<ResolveEntityResult> {
    const successfullyResolved: Record<string, ResolvedProfile> = {};
    const ignoredEntities: Record<string, PolicyEntityResolveError> = {};
    type resultType = Pick<Profile, 'Name' | 'Metadata'>;
    const profileQueryResults = Array<Promise<QueryResult<resultType>>>();
    const definitiveProfiles = this.config.profiles ?? {};
    Object.entries(definitiveProfiles).forEach(([profileName, profileDef]) => {
      if (profileDef.preset !== PermissionRiskLevelPresets.UNKNOWN) {
        const qr = Promise.resolve(
          context.targetOrgConnection.tooling.query<resultType>(
            `SELECT Name,Metadata FROM Profile WHERE Name = '${profileName}'`
          )
        );
        profileQueryResults.push(qr);
      } else {
        ignoredEntities[profileName] = {
          name: profileName,
          message: messages.getMessage('preset-unknown', ['Profile']),
        };
      }
    });
    const queryResults = await Promise.all(profileQueryResults);
    queryResults.forEach((qr) => {
      if (qr.records && qr.records.length > 0) {
        const record = qr.records[0];
        successfullyResolved[record.Name] = {
          name: record.Name,
          preset: definitiveProfiles[record.Name].preset,
          metadata: record.Metadata,
        };
      }
    });
    Object.keys(definitiveProfiles).forEach((profileName) => {
      if (successfullyResolved[profileName] === undefined && ignoredEntities[profileName] === undefined) {
        ignoredEntities[profileName] = { name: profileName, message: messages.getMessage('entity-not-found') };
      }
    });
    return { resolvedEntities: successfullyResolved, ignoredEntities: Object.values(ignoredEntities) };
  }
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
        resolved.push(new EnforceUserPermsClassificationOnProfiles(auditContext));
        break;
      case 'EnforceCustomPermissionClassifications':
        resolved.push(new EnforceCustomPermsClassificationOnProfiles(auditContext));
        break;
      default:
        break;
    }
  }
  return resolved;
}
