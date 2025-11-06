import { Connection } from '@salesforce/core';
import { PermissionsConfig } from '../core/file-mgmt/schema.js';
import { CUSTOM_PERMS_QUERY, PROFILES_QUERY } from '../core/constants.js';
import MDAPI from '../core/mdapi/mdapiRetriever.js';
import { CustomPermission, PermissionSet } from '../core/policies/salesforceStandardTypes.js';
import { classificationSorter, PermissionRiskLevel } from '../core/classification-types.js';
import { AuditInitPresets, loadPreset } from './presets.js';
import { UnclassifiedPerm } from './presets/none.js';

/**
 * Initialises a fresh set of user permissions from target org connection.
 *
 * @param con
 * @returns
 */
export async function initUserPermissions(con: Connection, preset?: AuditInitPresets): Promise<PermissionsConfig> {
  const describePerms = await parsePermsFromDescribe(con);
  const assignedPerms = await findAssignedPerms(con);
  const allPerms = { ...describePerms, ...assignedPerms };
  const presConfig = loadPreset(preset);
  const perms = presConfig.classifyUserPermissions(Object.values(allPerms));
  perms.sort(classificationSorter);
  const result: PermissionsConfig = { permissions: {} };
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
export async function initCustomPermissions(con: Connection): Promise<PermissionsConfig | undefined> {
  const result: PermissionsConfig = { permissions: {} };
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
  return rawLabel?.replace(/[ \t]+$|[\r\n]+/g, '');
}
