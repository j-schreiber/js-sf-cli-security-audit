import { Connection } from '@salesforce/core';
import Profiles from '../repositories/profiles/profiles.js';
import { CUSTOM_PERMS_QUERY, Permission, SfCustomPermission } from './orgDescribe.types.js';

export default class OrgDescribe {
  private customPermissions?: Map<string, Permission>;
  #userPermissions?: Promise<Map<string, Permission>>;

  public constructor(private con: Connection) {}

  private get userPermissions(): Promise<Map<string, Permission>> {
    return (this.#userPermissions ??= this.fetchUserPermissions());
  }

  /**
   * Analyses describe information and metadata to initialise
   * all permissions from the target org.
   *
   * @returns
   */
  public async getUserPermissions(): Promise<Permission[]> {
    const userPerms = await this.userPermissions;
    return Array.from(userPerms.values());
  }

  /**
   * Checks if the permission is valid for the org.
   *
   * @param permissionName
   */
  public async isValid(permissionName: string): Promise<boolean> {
    const userPerms = await this.userPermissions;
    return userPerms.has(permissionName);
  }

  /**
   * Finds all custom permissions that exist on the target org.
   *
   * @returns
   */
  public async getCustomPermissions(): Promise<Permission[]> {
    if (!this.customPermissions) {
      this.customPermissions = new Map<string, Permission>();
      const customPerms = await this.con.query<SfCustomPermission>(CUSTOM_PERMS_QUERY);
      if (customPerms.records.length > 0) {
        for (const cp of customPerms.records) {
          this.customPermissions.set(cp.DeveloperName, {
            name: cp.DeveloperName,
            label: cp.MasterLabel,
          });
        }
      }
    }
    return Array.from(this.customPermissions.values());
  }

  private async fetchUserPermissions(): Promise<Map<string, Permission>> {
    const describePerms = await parsePermsFromDescribe(this.con);
    const assignedPerms = await getUserPermsFromProfiles(this.con);
    return mergeMaps(assignedPerms, describePerms);
  }
}

function mergeMaps(...permMaps: Array<Map<string, Permission>>): Map<string, Permission> {
  return new Map(permMaps.flatMap((m) => [...m]));
}

async function parsePermsFromDescribe(con: Connection): Promise<Map<string, Permission>> {
  const permSet = await con.describe('PermissionSet');
  const describeAvailablePerms = new Map<string, Permission>();
  permSet.fields
    .filter((field) => field.name.startsWith('Permissions'))
    .forEach((field) => {
      const permName = field.name.replace('Permissions', '');
      describeAvailablePerms.set(permName, {
        label: sanitiseLabel(field.label),
        name: permName,
      });
    });
  return describeAvailablePerms;
}

async function getUserPermsFromProfiles(con: Connection): Promise<Map<string, Permission>> {
  const assignedPerms = new Map<string, Permission>();
  const profilesRepo = new Profiles(con);
  const profiles = await profilesRepo.resolve({ withMetadata: true });
  for (const profile of profiles.values()) {
    if (profile.metadata) {
      profile.metadata.userPermissions.forEach((userPerm) => {
        assignedPerms.set(userPerm.name, { name: userPerm.name, label: userPerm.name });
      });
    }
  }
  return assignedPerms;
}

function sanitiseLabel(rawLabel?: string): string | undefined {
  return rawLabel?.replaceAll(/[ \t]+$|[\r\n]+/g, '');
}
