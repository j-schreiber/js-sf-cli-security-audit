import { QueryResult } from '@jsforce/jsforce-node';
import { Messages } from '@salesforce/core';
import { Profile as ProfileMetadata } from '@jsforce/jsforce-node/lib/api/metadata.js';
import { EntityResolveError } from '../audit/types.js';
import { AuditRunConfig, ProfilesPolicyFileContent } from '../config/audit-run/schema.js';
import { isNullish } from '../utils.js';
import RuleRegistry from '../config/registries/ruleRegistry.js';
import ProfilesRuleRegistry from '../config/registries/profiles.js';
import { AuditContext } from './interfaces/policyRuleInterfaces.js';
import Policy, { ResolveEntityResult } from './policy.js';
import { Profile } from './salesforceStandardTypes.js';
import { PermissionRiskLevelPresets } from './types.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policies.general');

export type ResolvedProfile = {
  name: string;
  preset: string;
  metadata: ProfileMetadata;
};

export default class ProfilePolicy extends Policy {
  public constructor(
    public config: ProfilesPolicyFileContent,
    public auditConfig: AuditRunConfig,
    registry: RuleRegistry = new ProfilesRuleRegistry()
  ) {
    super(config, auditConfig, registry);
  }

  protected async resolveEntities(context: AuditContext): Promise<ResolveEntityResult> {
    const successfullyResolved: Record<string, ResolvedProfile> = {};
    const ignoredEntities: Record<string, EntityResolveError> = {};
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
        if (isNullish(record.Metadata)) {
          ignoredEntities[record.Name] = {
            name: record.Name,
            message: messages.getMessage('profile-invalid-no-metadata'),
          };
        } else {
          successfullyResolved[record.Name] = {
            name: record.Name,
            preset: definitiveProfiles[record.Name].preset,
            metadata: record.Metadata,
          };
        }
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
