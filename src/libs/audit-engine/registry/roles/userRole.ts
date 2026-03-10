import {
  PermissionClassifications,
  PermissionRiskLevel,
  RoleDefinitions,
  UserPrivilegeLevel,
} from '../shape/schema.js';
import { UserRoleCompareResult } from './roleManager.types.js';

export default class UserRole {
  public constructor(
    public roleName: string,
    private allowedPermissions: Set<string>,
    private roleOrdinalValue?: number
  ) {}

  public isAllowed(permissionName: string): boolean {
    return this.allowedPermissions.has(permissionName);
  }

  public compareWith(otherRole: UserRole): UserRoleCompareResult {
    const missingPermsInOther = new Array<string>();
    const missingPermsInThis = new Array<string>();
    const isOrdinallyHigher =
      this.roleOrdinalValue && otherRole.roleOrdinalValue ? this.roleOrdinalValue >= otherRole.roleOrdinalValue : true;
    const merged = new Set([...this.allowedPermissions, ...otherRole.allowedPermissions]);
    for (const perm of merged) {
      if (!this.allowedPermissions.has(perm)) {
        missingPermsInThis.push(perm);
      }
      if (!otherRole.allowedPermissions.has(perm)) {
        missingPermsInOther.push(perm);
      }
    }
    return {
      isSuperset: missingPermsInThis.length === 0 && isOrdinallyHigher,
      missingPermsInThis,
      missingPermsInOther,
    };
  }
}

export function newRoleFromDefinition(
  roleName: string,
  roleDef: RoleDefinitions['string'],
  perms?: PermissionClassifications
): UserRole {
  const allAllowed = new Set<string>();
  if (roleDef.allowedPermissions) {
    for (const permName of roleDef.allowedPermissions) {
      allAllowed.add(permName);
    }
  }
  if (perms) {
    for (const [permName, permDef] of Object.entries(perms)) {
      if (roleDef.allowedClassifications && roleDef.allowedClassifications.includes(permDef.classification)) {
        allAllowed.add(permName);
      }
    }
  }
  if (roleDef.deniedPermissions) {
    for (const permName of roleDef.deniedPermissions) {
      allAllowed.delete(permName);
    }
  }
  return new UserRole(roleName, allAllowed);
}

export function newRoleFromOrdinals(roleName: UserPrivilegeLevel, perms?: PermissionClassifications): UserRole {
  const roleOrdinalValue = resolvePresetOrdinalValue(roleName);
  if (!perms || roleName === UserPrivilegeLevel.UNKNOWN) {
    return new UserRole(roleName, new Set<string>(), roleOrdinalValue);
  }
  const allAllowed = new Set<string>();
  for (const [permName, permDef] of Object.entries(perms)) {
    if (roleOrdinalValue >= resolveRiskLevelOrdinalValue(permDef.classification)) {
      allAllowed.add(permName);
    }
  }
  return new UserRole(roleName, allAllowed, roleOrdinalValue);
}

function resolvePresetOrdinalValue(value: UserPrivilegeLevel): number {
  const indexOfValue = Object.values(UserPrivilegeLevel).indexOf(value);
  return Object.keys(UserPrivilegeLevel).length - indexOfValue;
}

function resolveRiskLevelOrdinalValue(value: string): number {
  return Object.keys(PermissionRiskLevel).length - Object.keys(PermissionRiskLevel).indexOf(value.toUpperCase());
}
