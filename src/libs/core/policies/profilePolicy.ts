import { Messages } from '@salesforce/core';
import { EntityResolveError } from '../result-types.js';
import { AuditRunConfig, BasePolicyFileContent, ProfilesClassificationContent } from '../file-mgmt/schema.js';
import { AuditContext } from '../registries/types.js';
import { UserPrivilegeLevel } from '../policy-types.js';
import { ProfilesRegistry } from '../registries/profiles.js';
import { Profile, Profiles } from '../salesforce-apis/index.js';
import Policy, { getTotal, ResolveEntityResult } from './policy.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policies.general');

export type ResolvedProfile = Profile & {
  role: string;
};

type ResolveState = {
  total: number;
  resolved: number;
};

export default class ProfilePolicy extends Policy<ResolvedProfile> {
  private resolveState: ResolveState = { total: 0, resolved: 0 };
  private readonly classifications: ProfilesClassificationContent;

  public constructor(
    public config: BasePolicyFileContent,
    public auditConfig: AuditRunConfig,
    registry = ProfilesRegistry
  ) {
    super(config, auditConfig, registry);
    this.classifications = this.auditConfig.classifications.profiles?.content ?? { profiles: {} };
    this.updateResolveState({ total: Object.keys(this.classifications.profiles).length });
  }

  protected async resolveEntities(context: AuditContext): Promise<ResolveEntityResult<ResolvedProfile>> {
    this.updateResolveState({ resolved: 0 });
    const profilesRepo = new Profiles(context.targetOrgConnection);
    const allProfiles = await profilesRepo.resolve();
    const ignoredEntities: Record<string, EntityResolveError> = {};
    const classifiedProfiles: string[] = [];
    for (const [profileName, profileDef] of Object.entries(this.classifications.profiles)) {
      if (profileDef.role === UserPrivilegeLevel.UNKNOWN) {
        ignoredEntities[profileName] = {
          name: profileName,
          message: messages.getMessage('preset-unknown', ['Profile']),
        };
      } else if (!allProfiles.has(profileName)) {
        ignoredEntities[profileName] = {
          name: profileName,
          message: messages.getMessage('entity-not-found'),
        };
      } else {
        classifiedProfiles.push(profileName);
      }
    }
    for (const profile of allProfiles.values()) {
      if (this.classifications.profiles[profile.name] === undefined) {
        ignoredEntities[profile.name] = {
          name: profile.name,
          message: messages.getMessage('entity-not-classified'),
        };
      }
    }
    this.updateResolveState({ total: Object.keys(ignoredEntities).length + classifiedProfiles.length });
    const profiles = await profilesRepo.resolve({ withMetadata: true, filterNames: classifiedProfiles });
    const resolvedEntities: Record<string, ResolvedProfile> = {};
    classifiedProfiles.forEach((profileName) => {
      if (profiles.has(profileName) && profiles.get(profileName)) {
        resolvedEntities[profileName] = {
          ...profiles.get(profileName)!,
          role: this.classifications.profiles[profileName].role,
        };
      } else {
        ignoredEntities[profileName] = {
          name: profileName,
          message: messages.getMessage('profile-invalid-no-metadata'),
        };
      }
    });
    const result = { resolvedEntities, ignoredEntities: Object.values(ignoredEntities) };
    this.updateResolveState({ resolved: getTotal(result) });
    return result;
  }

  private updateResolveState(update: Partial<ResolveState>): void {
    this.resolveState = { ...this.resolveState, ...update };
    this.emit('entityresolve', this.resolveState);
  }
}
