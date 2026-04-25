import { PermissionRiskLevel, UserPrivilegeLevel } from '../audit-engine/index.js';
import { OrgDescribe, PermissionSets, Profiles, SfConnection, Users } from '../../salesforce/index.js';
import { Inventories, Shapes } from '../audit-engine/registry/definitions.js';
import { loadPreset } from './presets.js';
import {
  AuditInitPresets,
  NamedPermissionClassification,
  PermissionClassifications,
  PermsetClassifications,
  ProfileClassifications,
  UserClassifications,
} from './init.types.js';

export type Initialiser = (con: SfConnection, preset?: AuditInitPresets) => Promise<unknown>;

export const ShapeInitialisers: Record<Shapes, Initialiser> = {
  userPermissions: initUserPermissions,
  customPermissions: initCustomPermissions,
};

export const InventoryInitialisers: Record<Inventories, Initialiser> = {
  profiles: initProfiles,
  permissionSets: initPermissionSets,
  users: initUsers,
};

async function initUserPermissions(con: SfConnection, preset?: AuditInitPresets): Promise<PermissionClassifications> {
  const orgManager = await OrgDescribe.create(con);
  const userPerms = orgManager.getUserPermissions();
  const presConfig = loadPreset(preset);
  const perms = presConfig.classifyUserPermissions(userPerms);
  perms.sort(classificationSorter);
  const result: PermissionClassifications = {};
  perms.forEach(
    (perm) =>
      (result[perm.name] = {
        label: perm.label,
        classification: perm.classification,
        reason: perm.reason,
      })
  );
  return result;
}

async function initCustomPermissions(con: SfConnection): Promise<PermissionClassifications | undefined> {
  const result: PermissionClassifications = {};
  const orgManager = await OrgDescribe.create(con);
  const customPerms = orgManager.getCustomPermissions();
  if (customPerms.length === 0) {
    return undefined;
  }
  const perms = customPerms.map((cp) => ({
    ...cp,
    classification: PermissionRiskLevel.UNKNOWN,
  }));
  perms.forEach(
    (perm) =>
      (result[perm.name] = {
        label: perm.label,
        classification: perm.classification,
      })
  );
  return result;
}

async function initProfiles(targetOrgCon: SfConnection): Promise<ProfileClassifications> {
  const profilesRepo = new Profiles(targetOrgCon);
  const profiles = await profilesRepo.resolve();
  const content: ProfileClassifications = {};
  for (const profileName of profiles.keys()) {
    content[profileName] = { role: UserPrivilegeLevel.UNKNOWN };
  }
  return content;
}

async function initPermissionSets(targetOrgCon: SfConnection): Promise<PermsetClassifications> {
  const permsetsRepo = new PermissionSets(targetOrgCon);
  const permsets = await permsetsRepo.resolve({ isCustomOnly: true });
  const content: PermsetClassifications = {};
  for (const permsetName of permsets.keys()) {
    content[permsetName] = { role: UserPrivilegeLevel.UNKNOWN };
  }
  return content;
}

async function initUsers(targetOrgCon: SfConnection): Promise<UserClassifications> {
  const usersRepo = new Users(targetOrgCon);
  const users = await usersRepo.resolve();
  const content: UserClassifications = {};
  for (const username of users.keys()) content[username] = { role: UserPrivilegeLevel.STANDARD_USER };
  return content;
}

function resolveRiskLevelOrdinalValue(value: string): number {
  return Object.keys(PermissionRiskLevel).indexOf(value.toUpperCase());
}

const classificationSorter = (a: NamedPermissionClassification, b: NamedPermissionClassification): number =>
  resolveRiskLevelOrdinalValue(a.classification) - resolveRiskLevelOrdinalValue(b.classification);
