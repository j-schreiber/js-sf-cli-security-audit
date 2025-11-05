import { Messages } from '@salesforce/core';
import { EntityResolveError } from '../core/result-types.js';
import { AuditRunConfig, ProfilesPolicyFileContent } from '../core/file-mgmt/schema.js';
import MDAPI from '../core/mdapi/mdapiRetriever.js';
import { AuditContext, RuleRegistries } from '../core/registries/types.js';
import { ProfilesRiskPreset } from '../core/policy-types.js';
import { ResolvedProfile } from '../core/registries/profiles.js';
import Policy, { getTotal, ResolveEntityResult } from './policy.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policies.general');

export default class ProfilePolicy extends Policy<ResolvedProfile> {
  private totalEntities: number;
  public constructor(
    public config: ProfilesPolicyFileContent,
    public auditConfig: AuditRunConfig,
    registry = RuleRegistries.Profiles
  ) {
    super(config, auditConfig, registry);
    this.totalEntities = this.config.profiles ? Object.keys(this.config.profiles).length : 0;
  }

  protected async resolveEntities(context: AuditContext): Promise<ResolveEntityResult<ResolvedProfile>> {
    this.emit('entityresolve', {
      total: this.totalEntities,
      resolved: 0,
    });
    const successfullyResolved: Record<string, ResolvedProfile> = {};
    const ignoredEntities: Record<string, EntityResolveError> = {};
    const definitiveProfiles = this.config.profiles ?? {};
    const classifiedProfiles: string[] = [];
    Object.entries(definitiveProfiles).forEach(([profileName, profileDef]) => {
      if (profileDef.preset === ProfilesRiskPreset.UNKNOWN) {
        ignoredEntities[profileName] = {
          name: profileName,
          message: messages.getMessage('preset-unknown', ['Profile']),
        };
      } else {
        classifiedProfiles.push(profileName);
      }
    });
    const mdapi = new MDAPI(context.targetOrgConnection);
    const resolvedProfiles = await mdapi.resolve('Profile', classifiedProfiles);
    classifiedProfiles.forEach((profileName) => {
      const resolvedProfile = resolvedProfiles[profileName];
      if (!resolvedProfile) {
        ignoredEntities[profileName] = {
          name: profileName,
          message: messages.getMessage('entity-not-found'),
        };
      } else {
        successfullyResolved[profileName] = {
          name: profileName,
          preset: definitiveProfiles[profileName].preset,
          metadata: resolvedProfile,
        };
      }
    });
    const result = { resolvedEntities: successfullyResolved, ignoredEntities: Object.values(ignoredEntities) };
    this.emit('entityresolve', {
      total: this.totalEntities,
      resolved: getTotal(result),
    });
    return result;
  }
}
