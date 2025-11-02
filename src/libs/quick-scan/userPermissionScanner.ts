import { Connection } from '@salesforce/core';
import { Profile, PermissionSet as PermissionSetMetadata } from '@jsforce/jsforce-node/lib/api/metadata.js';
import MDAPI from '../core/mdapi/mdapiRetriever.js';
import { PERMISSION_SETS_QUERY, PROFILES_QUERY } from '../core/constants.js';
import { PermissionSet } from '../policies/salesforceStandardTypes.js';
import { QuickScanOptions, QuickScanResult } from './types.js';

export default class UserPermissionScanner {
  public static async quickScan(opts: QuickScanOptions): Promise<QuickScanResult> {
    // query all profiles and permission sets
    // resolve metadata for each entity
    // search for perm
    const resolvedProfiles = await resolveProfiles(opts.targetOrg);
    const resolvedPermSets = await resolvePermissionSets(opts.targetOrg);
    const scanResult: QuickScanResult = {};
    opts.permissions.forEach((permName) => {
      const profiles = findGrantingEntities(permName, resolvedProfiles);
      const permissionSets = findGrantingEntities(permName, resolvedPermSets);
      scanResult[permName] = { permissionSets, profiles };
    });
    return scanResult;
  }
}

async function resolveProfiles(targetOrg: Connection): Promise<Record<string, Profile>> {
  const profiles = await targetOrg.query<PermissionSet>(PROFILES_QUERY);
  const mdapi = new MDAPI(targetOrg);
  const resolved = await mdapi.resolve(
    'Profile',
    profiles.records.map((permsetRecord) => permsetRecord.Profile.Name)
  );
  return resolved;
}

async function resolvePermissionSets(targetOrg: Connection): Promise<Record<string, PermissionSetMetadata>> {
  const permSets = await targetOrg.query<PermissionSet>(PERMISSION_SETS_QUERY);
  const mdapi = new MDAPI(targetOrg);
  const resolved = await mdapi.resolve(
    'PermissionSet',
    permSets.records.map((permsetRecord) => permsetRecord.Name)
  );
  return resolved;
}

function findGrantingEntities(
  permName: string,
  resolvedEntities: Record<string, Profile | PermissionSetMetadata>
): string[] {
  const entities = new Set<string>();
  Object.entries(resolvedEntities).forEach(([entityName, metadata]) => {
    const userPerms = metadata.userPermissions.map((userPerm) => userPerm.name);
    if (userPerms.includes(permName)) {
      entities.add(entityName);
    }
  });
  return Array.from(entities);
}
