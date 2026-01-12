import { Connection } from '@salesforce/core';
import MDAPI from '../../mdapi/mdapiRetriever.js';
import { PROFILES_QUERY } from './queries.js';
import { PermissionSet, Profile, ResolveProfilesOptions, ResolveProfilesOptionsSchema } from './profiles.types.js';

export default class Profiles {
  private readonly mdapi: MDAPI;

  public constructor(private readonly con: Connection) {
    this.mdapi = MDAPI.create(this.con);
  }

  /**
   * Resolves all profiles from the org, optionally with metadata
   *
   * @param opts
   * @returns
   */
  public async resolve(opts?: ResolveProfilesOptions): Promise<Map<string, Profile>> {
    const definitiveOpts = ResolveProfilesOptionsSchema.parse(opts ?? {});
    const result = new Map<string, Profile>();
    const profilePermsets = await this.con.query<PermissionSet>(PROFILES_QUERY);
    const resolved = definitiveOpts.withMetadata
      ? await this.mdapi.resolve(
          'Profile',
          profilePermsets.records.map((permsetRecord) => permsetRecord.Profile.Name)
        )
      : {};
    for (const sfPermSet of profilePermsets.records) {
      result.set(sfPermSet.Profile.Name, {
        profileId: sfPermSet.Profile.Id,
        userType: sfPermSet.Profile.UserType,
        name: sfPermSet.Profile.Name,
        metadata: resolved[sfPermSet.Profile.Name],
      });
    }
    return result;
  }
}
