import { Messages } from '@salesforce/core';
import { EntityResolveError } from '../result-types.js';
import { AuditRunConfig, BasePolicyFileContent, ProfilesClassificationContent } from '../file-mgmt/schema.js';
import MDAPI from '../mdapi/mdapiRetriever.js';
import { AuditContext } from '../registries/types.js';
import { ProfilesRiskPreset } from '../policy-types.js';
import { ProfilesRegistry, ResolvedProfile } from '../registries/profiles.js';
import Policy, { getTotal, ResolveEntityResult } from './policy.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policies.general');

export default class ProfilePolicy extends Policy<ResolvedProfile> {
  private readonly totalEntities: number;
  private readonly classifications: ProfilesClassificationContent;

  public constructor(
    public config: BasePolicyFileContent,
    public auditConfig: AuditRunConfig,
    registry = ProfilesRegistry
  ) {
    super(config, auditConfig, registry);
    this.classifications = this.auditConfig.classifications.profiles?.content ?? { profiles: {} };
    this.totalEntities = Object.keys(this.classifications.profiles).length;
  }

  protected async resolveEntities(context: AuditContext): Promise<ResolveEntityResult<ResolvedProfile>> {
    this.emit('entityresolve', {
      total: this.totalEntities,
      resolved: 0,
    });
    const successfullyResolved: Record<string, ResolvedProfile> = {};
    const ignoredEntities: Record<string, EntityResolveError> = {};
    const classifiedProfiles: string[] = [];
    Object.entries(this.classifications.profiles).forEach(([profileName, profileDef]) => {
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
      if (resolvedProfile) {
        successfullyResolved[profileName] = {
          name: profileName,
          preset: this.classifications.profiles[profileName].preset,
          metadata: resolvedProfile,
        };
      } else {
        ignoredEntities[profileName] = {
          name: profileName,
          message: messages.getMessage('entity-not-found'),
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
