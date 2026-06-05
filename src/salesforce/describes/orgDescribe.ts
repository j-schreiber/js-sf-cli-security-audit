import Profiles from '../repositories/profiles/profiles.js';
import SfConnection from '../connection.js';
import { CUSTOM_PERMS_QUERY, Permission, SfCustomPermission, SObjectsDescribeResult } from './orgDescribe.types.js';

/** Minimum length for perm label to start fuzzy matching */
const FUZZY_MATCH_MIN_LENGTH = 15;
export default class OrgDescribe {
  /**
   * Caches initialised OrgDescribes by username.
   */
  public static orgCache = new Map<string, OrgDescribe>();
  private customPermissions!: Map<string, Permission>;
  private userPermissions!: Map<string, Permission>;

  private constructor(private readonly con: SfConnection) {}

  /**
   * Initialises a new OrgDescribe instance from an existing connection
   * and caches it for repeated access.
   *
   * @param con
   * @returns
   */
  public static async create(con: SfConnection): Promise<OrgDescribe> {
    const maybeCache = this.orgCache.get(con.coreConnection.instanceUrl);
    if (maybeCache) {
      return maybeCache;
    }
    const inst = new OrgDescribe(con);
    inst.userPermissions = await fetchUserPermissions(con);
    inst.customPermissions = await fetchCustomPermissions(con);
    this.orgCache.set(con.coreConnection.instanceUrl, inst);
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
   * Checks if the permission is valid custom permission for the org
   *
   * @param permissionName
   */
  public isValidCustomPerm(permissionName: string): boolean {
    return (
      this.customPermissions.has(permissionName.toLowerCase()) &&
      this.customPermissions.get(permissionName.toLowerCase())?.name === permissionName
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

  /**
   * Sanitise and describe a list of sobject names and returns
   * fully qualified sobject describes for each valid name.
   *
   * @param objectNames
   * @returns
   */
  public async describeSObjects(objectNames: string[]): Promise<SObjectsDescribeResult> {
    const result: SObjectsDescribeResult = { successes: [], errors: [], describes: {} };
    const normalisedNames = normalise(objectNames);
    const describePromises = normalisedNames.map((uniqueObjectName) => this.con.describe(uniqueObjectName));
    const describes = await Promise.allSettled(describePromises);
    for (const settledPromise of describes) {
      if (settledPromise.status === 'fulfilled') {
        result.successes.push(settledPromise.value.name);
        result.describes[settledPromise.value.name.toLowerCase()] = settledPromise.value;
      } else {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
        const { reason } = settledPromise;
        const name = normalisedNames[describes.indexOf(settledPromise)];
        const reasonMessage = hasMessage(reason) ? reason.message : 'Failed to resolve with unknown error';
        result.errors.push({ name, reason: reasonMessage });
      }
    }
    return result;
  }
}

function hasMessage(obj: unknown): obj is { message: string } {
  return typeof obj === 'object' && obj !== null && 'message' in obj;
}

async function fetchUserPermissions(con: SfConnection): Promise<Map<string, Permission>> {
  const describePerms = await parsePermsFromDescribe(con);
  const assignedPerms = await getUserPermsFromProfiles(con);
  return mergeMaps(assignedPerms, describePerms);
}

async function fetchCustomPermissions(con: SfConnection): Promise<Map<string, Permission>> {
  const result = new Map<string, Permission>();
  const customPerms = await con.query<SfCustomPermission>(CUSTOM_PERMS_QUERY);
  if (customPerms.records.length > 0) {
    for (const cp of customPerms.records) {
      result.set(cp.DeveloperName.toLowerCase(), {
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

function normalise(anyStrings: string[]): string[] {
  return Array.from(new Set<string>(anyStrings.map((inputString) => inputString.toLowerCase())));
}

async function parsePermsFromDescribe(con: SfConnection): Promise<Map<string, Permission>> {
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

async function getUserPermsFromProfiles(con: SfConnection): Promise<Map<string, Permission>> {
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
