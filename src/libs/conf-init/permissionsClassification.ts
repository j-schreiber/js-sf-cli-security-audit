import { Connection } from '@salesforce/core';
import {
  PermissionsClassificationContent,
  PermissionSetsClassificationContent,
  ProfilesClassificationContent,
  UsersClassificationContent,
} from '../core/file-mgmt/schema.js';
import { CUSTOM_PERMS_QUERY, PERMISSION_SETS_QUERY, PROFILES_QUERY } from '../core/constants.js';
import MDAPI from '../core/mdapi/mdapiRetriever.js';
import { CustomPermission, PermissionSet } from '../core/policies/salesforceStandardTypes.js';
import { classificationSorter, PermissionRiskLevel } from '../core/classification-types.js';
import { Users } from '../core/salesforce-apis/index.js';
import { UserPrivilegeLevel } from '../core/policy-types.js';
import { AuditInitPresets, loadPreset } from './presets.js';
import { UnclassifiedPerm } from './presets/none.js';

/**
 * Initialises a fresh set of user permissions from target org connection.
 *
 * @param con
 * @returns
 */
export async function initUserPermissions(
  con: Connection,
  preset?: AuditInitPresets
): Promise<PermissionsClassificationContent> {
  const describePerms = await parsePermsFromDescribe(con);
  const assignedPerms = await findAssignedPerms(con);
  const allPerms = { ...describePerms, ...assignedPerms };
  const presConfig = loadPreset(preset);
  const perms = presConfig.classifyUserPermissions(Object.values(allPerms));
  perms.sort(classificationSorter);
  const result: PermissionsClassificationContent = { permissions: {} };
  perms.forEach(
    (perm) =>
      (result.permissions[perm.name] = {
        label: sanitiseLabel(perm.label),
        classification: perm.classification,
        reason: perm.reason,
      })
  );
  return result;
}

/**
 * Initialises a fresh set of custom permissions from the target org
 *
 * @param con
 * @returns
 */
export async function initCustomPermissions(con: Connection): Promise<PermissionsClassificationContent | undefined> {
  const result: PermissionsClassificationContent = { permissions: {} };
  const customPerms = await con.query<CustomPermission>(CUSTOM_PERMS_QUERY);
  if (customPerms.records.length === 0) {
    return undefined;
  }
  const perms = customPerms.records.map((cp) => ({
    name: cp.DeveloperName,
    label: cp.MasterLabel,
    classification: PermissionRiskLevel.UNKNOWN,
  }));
  perms.forEach(
    (perm) =>
      (result.permissions[perm.name] = {
        label: perm.label,
        classification: perm.classification,
      })
  );
  return result;
}

/**
 * Initialises a profiles classification with all profiles from the org.
 *
 * @param targetOrgCon
 * @returns
 */
export async function initProfiles(targetOrgCon: Connection): Promise<ProfilesClassificationContent> {
  const profiles = await targetOrgCon.query<PermissionSet>(PROFILES_QUERY);
  const content: ProfilesClassificationContent = { profiles: {} };
  profiles.records.forEach((permsetRecord) => {
    content.profiles[permsetRecord.Profile.Name] = { role: UserPrivilegeLevel.UNKNOWN };
  });
  return content;
}

/**
 * Initialises permission set classification with all perm sets
 *
 * @param targetOrgCon
 * @returns
 */
export async function initPermissionSets(targetOrgCon: Connection): Promise<PermissionSetsClassificationContent> {
  const permSets = await targetOrgCon.query<PermissionSet>(PERMISSION_SETS_QUERY);
  const content: PermissionSetsClassificationContent = { permissionSets: {} };
  permSets.records
    .filter((permsetRecord) => permsetRecord.IsCustom)
    .forEach((permsetRecord) => {
      content.permissionSets[permsetRecord.Name] = { role: UserPrivilegeLevel.UNKNOWN };
    });
  return content;
}

/**
 * Initialises users classification with all users classified as standard users.
 *
 * @param targetOrgCon
 */
export async function initUsers(targetOrgCon: Connection): Promise<UsersClassificationContent> {
  const usersRepo = new Users(targetOrgCon);
  const users = await usersRepo.resolve();
  const content: UsersClassificationContent = {
    users: {},
  };
  for (const username of users.keys()) content.users[username] = { role: UserPrivilegeLevel.STANDARD_USER };
  return content;
}

async function parsePermsFromDescribe(con: Connection): Promise<Record<string, UnclassifiedPerm>> {
  const permSet = await con.describe('PermissionSet');
  const describeAvailablePerms: Record<string, UnclassifiedPerm> = {};
  permSet.fields
    .filter((field) => field.name.startsWith('Permissions'))
    .forEach((field) => {
      const permName = field.name.replace('Permissions', '');
      describeAvailablePerms[permName] = {
        label: field.label,
        name: permName,
      };
    });
  return describeAvailablePerms;
}

async function findAssignedPerms(con: Connection): Promise<Record<string, UnclassifiedPerm>> {
  const assignedPerms: Record<string, UnclassifiedPerm> = {};
  const profiles = await con.query<PermissionSet>(PROFILES_QUERY);
  if (profiles.records?.length > 0) {
    const mdapi = new MDAPI(con);
    const resolvedProfiles = await mdapi.resolve(
      'Profile',
      profiles.records.map((p) => p.Profile.Name)
    );
    Object.values(resolvedProfiles).forEach((profile) => {
      profile.userPermissions.forEach((userPerm) => {
        assignedPerms[userPerm.name] = { name: userPerm.name };
      });
    });
  }
  return assignedPerms;
}

function sanitiseLabel(rawLabel?: string): string | undefined {
  return rawLabel?.replaceAll(/[ \t]+$|[\r\n]+/g, '');
}
