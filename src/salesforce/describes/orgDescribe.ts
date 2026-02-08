import { Connection } from '@salesforce/core';
import Profiles from '../repositories/profiles/profiles.js';
import { CUSTOM_PERMS_QUERY, Permission, SfCustomPermission } from './orgDescribe.types.js';

export default class OrgDescribe {
  private userPermissions?: Permission[];
  private customPermissions?: Permission[];

  public constructor(private con: Connection) {}

  /**
   * Analyses describe information and metadata to initialise
   * all permissions from the target org.
   *
   * @returns
   */
  public async getUserPermissions(): Promise<Permission[]> {
    if (!this.userPermissions) {
      const describePerms = await parsePermsFromDescribe(this.con);
      const assignedPerms = await getUserPermsFromProfiles(this.con);
      this.userPermissions = mergePermissions(assignedPerms, describePerms);
    }
    return this.userPermissions;
  }

  /**
   * Finds all custom permissions that exist on the target org.
   *
   * @returns
   */
  public async getCustomPermissions(): Promise<Permission[]> {
    if (!this.customPermissions) {
      const customPerms = await this.con.query<SfCustomPermission>(CUSTOM_PERMS_QUERY);
      if (customPerms.records.length === 0) {
        this.customPermissions = [];
      } else {
        this.customPermissions = customPerms.records.map((cp) => ({
          name: cp.DeveloperName,
          label: cp.MasterLabel,
        }));
      }
    }
    return this.customPermissions;
  }
}

function mergePermissions(...permMaps: Array<Map<string, Permission>>): Permission[] {
  const mergedPerms = new Map(permMaps.flatMap((m) => [...m]));
  return Array.from(mergedPerms.values());
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
