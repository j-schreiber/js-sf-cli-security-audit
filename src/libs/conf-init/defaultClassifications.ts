import { Connection } from '@salesforce/core';
import { Classifications, PermissionRiskLevel, UserPrivilegeLevel } from '../audit-engine/index.js';
import { OrgDescribe, PermissionSets, Profiles, Users } from '../../salesforce/index.js';
import { loadPreset } from './presets.js';
import {
  AuditInitPresets,
  NamedPermissionClassification,
  PermissionClassifications,
  PermsetClassifications,
  ProfileClassifications,
  UserClassifications,
} from './init.types.js';

type ClassificationDefinition = {
  initialiser: (con: Connection, preset?: AuditInitPresets) => unknown;
};

export const ClassificationInitDefinitions: Record<Classifications, ClassificationDefinition> = {
  userPermissions: {
    initialiser: initUserPermissions,
  },
  customPermissions: {
    initialiser: initCustomPermissions,
  },
  profiles: {
    initialiser: initProfiles,
  },
  permissionSets: {
    initialiser: initPermissionSets,
  },
  users: {
    initialiser: initUsers,
  },
};

async function initUserPermissions(con: Connection, preset?: AuditInitPresets): Promise<PermissionClassifications> {
  const orgManager = new OrgDescribe(con);
  const userPerms = await orgManager.getUserPermissions();
  const presConfig = loadPreset(preset);
  const perms = presConfig.classifyUserPermissions(userPerms);
  perms.sort(classificationSorter);
  const result: PermissionClassifications = { permissions: {} };
  perms.forEach(
    (perm) =>
      (result.permissions[perm.name] = {
        label: perm.label,
        classification: perm.classification,
        reason: perm.reason,
      })
  );
  return result;
}

async function initCustomPermissions(con: Connection): Promise<PermissionClassifications | undefined> {
  const result: PermissionClassifications = { permissions: {} };
  const orgManager = new OrgDescribe(con);
  const customPerms = await orgManager.getCustomPermissions();
  if (customPerms.length === 0) {
    return undefined;
  }
  const perms = customPerms.map((cp) => ({
    ...cp,
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

async function initProfiles(targetOrgCon: Connection): Promise<ProfileClassifications> {
  const profilesRepo = new Profiles(targetOrgCon);
  const profiles = await profilesRepo.resolve();
  const content: ProfileClassifications = { profiles: {} };
  for (const profileName of profiles.keys()) {
    content.profiles[profileName] = { role: UserPrivilegeLevel.UNKNOWN };
  }
  return content;
}

async function initPermissionSets(targetOrgCon: Connection): Promise<PermsetClassifications> {
  const permsetsRepo = new PermissionSets(targetOrgCon);
  const permsets = await permsetsRepo.resolve({ isCustomOnly: true });
  const content: PermsetClassifications = { permissionSets: {} };
  for (const permsetName of permsets.keys()) {
    content.permissionSets[permsetName] = { role: UserPrivilegeLevel.UNKNOWN };
  }
  return content;
}

async function initUsers(targetOrgCon: Connection): Promise<UserClassifications> {
  const usersRepo = new Users(targetOrgCon);
  const users = await usersRepo.resolve();
  const content: UserClassifications = {
    users: {},
  };
  for (const username of users.keys()) content.users[username] = { role: UserPrivilegeLevel.STANDARD_USER };
  return content;
}

function resolveRiskLevelOrdinalValue(value: string): number {
  return Object.keys(PermissionRiskLevel).indexOf(value.toUpperCase());
}

const classificationSorter = (a: NamedPermissionClassification, b: NamedPermissionClassification): number =>
  resolveRiskLevelOrdinalValue(a.classification) - resolveRiskLevelOrdinalValue(b.classification);
