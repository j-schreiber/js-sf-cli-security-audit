import { Connection } from '@salesforce/core';
import Profiles from '../repositories/profiles/profiles.js';
import { CUSTOM_PERMS_QUERY, Permission, SfCustomPermission } from './orgDescribe.types.js';

/** Minimum length for perm label to start fuzzy matching */
const FUZZY_MATCH_MIN_LENGTH = 15;
export default class OrgDescribe {
  private customPermissions!: Map<string, Permission>;
  private userPermissions!: Map<string, Permission>;

  private constructor() {}

  public static async create(con: Connection): Promise<OrgDescribe> {
    const inst = new OrgDescribe();
    inst.userPermissions = await fetchUserPermissions(con);
    inst.customPermissions = await fetchCustomPermissions(con);
    return inst;
  }

  /**
   * Tries to find a user permission based on unsanitized input. Searches
   * by exact match (fastest) or tries fuzzy matching by name and label.
   *
   * @param maybeValidName
   * @returns A valid user permission or undefined, if the name cannot be resolved
   */
  public findUserPermission(maybeValidName: string): Permission | undefined {
    const canonicalName = maybeValidName.toLowerCase().replaceAll(/[\s.]/g, '');
    if (this.userPermissions.has(canonicalName)) {
      return this.userPermissions.get(canonicalName);
    }
    for (const perm of this.userPermissions.values()) {
      if (!perm.label) {
        continue;
      }
      const canonicalLabel = perm.label.toLowerCase().replaceAll(/[\s.]/g, '');
      if (
        canonicalLabel === canonicalName ||
        (canonicalName.length >= FUZZY_MATCH_MIN_LENGTH && canonicalLabel.startsWith(canonicalName))
      ) {
        return perm;
      }
    }
  }

  /**
   * Analyses describe information and metadata to initialise
   * all permissions from the target org.
   *
   * @returns
   */
  public getUserPermissions(): Permission[] {
    return Array.from(this.userPermissions.values());
  }

  /**
   * Checks if the permission is valid for the org.
   *
   * @param permissionName
   */
  public isValid(permissionName: string): boolean {
    return (
      this.userPermissions.has(permissionName.toLowerCase()) &&
      this.userPermissions.get(permissionName.toLowerCase())?.name === permissionName
    );
  }

  /**
   * Finds all custom permissions that exist on the target org.
   *
   * @returns
   */
  public getCustomPermissions(): Permission[] {
    return Array.from(this.customPermissions.values());
  }
}

async function fetchUserPermissions(con: Connection): Promise<Map<string, Permission>> {
  const describePerms = await parsePermsFromDescribe(con);
  const assignedPerms = await getUserPermsFromProfiles(con);
  return mergeMaps(assignedPerms, describePerms);
}

async function fetchCustomPermissions(con: Connection): Promise<Map<string, Permission>> {
  const result = new Map<string, Permission>();
  const customPerms = await con.query<SfCustomPermission>(CUSTOM_PERMS_QUERY);
  if (customPerms.records.length > 0) {
    for (const cp of customPerms.records) {
      result.set(cp.DeveloperName, {
        name: cp.DeveloperName,
        label: cp.MasterLabel,
      });
    }
  }
  return result;
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
      describeAvailablePerms.set(permName.toLowerCase(), {
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
        assignedPerms.set(userPerm.name.toLowerCase(), { name: userPerm.name, label: userPerm.name });
      });
    }
  }
  return assignedPerms;
}

function sanitiseLabel(rawLabel?: string): string | undefined {
  return rawLabel?.replaceAll(/[ \t]+$|[\r\n]+/g, '');
}
