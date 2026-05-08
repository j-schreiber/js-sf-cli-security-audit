import { merge } from '@salesforce/kit';
import { Messages } from '@salesforce/core';
import {
  PermissionClassifications,
  PermissionRiskLevel,
  UserPrivilegeLevel,
  isPermissionControl,
  PermissionControlSection,
} from '../shape/schema.js';
import {
  DefinitiveRoleDefinition,
  OrgAuditControls,
  RoleManagerConfig,
  TypedPermission,
  UserRoleCompareResult,
} from './roleManager.types.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.enforceClassificationPresets');

type UserRolePermissions = {
  allowed: Set<string>;
  denied: Set<string>;
};

export default class UserRole {
  public constructor(
    public roleName: string,
    private userPermissions: UserRolePermissions,
    private customPermissions: UserRolePermissions,
    private roleOrdinalValue?: number
  ) {}

  /**
   * Evaluates if a permission is explicitly denied
   *
   * @param permission
   * @returns
   */
  public isDenied(permission: TypedPermission): boolean {
    if (permission.type === 'customPermissions') {
      return this.customPermissions.denied.has(permission.name.toLowerCase());
    } else {
      return this.userPermissions.denied.has(permission.name.toLowerCase());
    }
  }

  /**
   * Evaluates if a permission of type userPermission or customPermission
   * is allowed for the role.
   *
   * @param permission
   * @returns
   */
  public isAllowed(permission: TypedPermission): boolean {
    if (permission.type === 'customPermissions') {
      return this.customPermissions.allowed.has(permission.name);
    } else {
      return this.userPermissions.allowed.has(permission.name);
    }
  }

  public compareWith(otherRole: UserRole): UserRoleCompareResult {
    const missingPermsInOther = new Array<string>();
    const missingPermsInThis = new Array<string>();
    const isOrdinallyHigher =
      this.roleOrdinalValue && otherRole.roleOrdinalValue ? this.roleOrdinalValue >= otherRole.roleOrdinalValue : true;
    const merged = new Set([...this.userPermissions.allowed, ...otherRole.userPermissions.allowed]);
    for (const perm of merged) {
      if (!this.userPermissions.allowed.has(perm)) {
        missingPermsInThis.push(perm);
      }
      if (!otherRole.userPermissions.allowed.has(perm)) {
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

export function newRoleFromDefinition(roleName: string, config: RoleManagerConfig): UserRole {
  const { permissions } = resolveRole(roleName, config.controls);
  const userPerms = buildAllowedPerms(
    permissions?.userPermissions,
    config.shape.userPermissions,
    permissions?.allowedClassifications
  );
  const customPerms = buildAllowedPerms(
    permissions?.customPermissions,
    config.shape.customPermissions,
    permissions?.allowedClassifications
  );

  return new UserRole(roleName, userPerms, customPerms);
}

export function newRoleFromOrdinals(roleName: UserPrivilegeLevel, perms?: PermissionClassifications): UserRole {
  const roleOrdinalValue = resolvePresetOrdinalValue(roleName);
  if (!perms || roleName === UserPrivilegeLevel.UNKNOWN) {
    return new UserRole(
      roleName,
      { allowed: new Set<string>(), denied: new Set<string>() },
      { allowed: new Set<string>(), denied: new Set<string>() },
      roleOrdinalValue
    );
  }
  const allAllowed = new Set<string>();
  for (const [permName, permDef] of Object.entries(perms)) {
    if (roleOrdinalValue >= resolveRiskLevelOrdinalValue(permDef.classification)) {
      allAllowed.add(permName);
    }
  }
  return new UserRole(
    roleName,
    { allowed: allAllowed, denied: new Set<string>() },
    { allowed: new Set<string>(), denied: new Set<string>() },
    roleOrdinalValue
  );
}

function resolvePresetOrdinalValue(value: UserPrivilegeLevel): number {
  const indexOfValue = Object.values(UserPrivilegeLevel).indexOf(value);
  return Object.keys(UserPrivilegeLevel).length - indexOfValue;
}

function resolveRiskLevelOrdinalValue(value: string): number {
  return Object.keys(PermissionRiskLevel).length - Object.keys(PermissionRiskLevel).indexOf(value.toUpperCase());
}

function resolveRole(roleName: string, controls: OrgAuditControls): DefinitiveRoleDefinition {
  const rawRoleDef = controls.roles?.[roleName];
  if (!rawRoleDef) {
    throw messages.createError('TriedToAccessRoleThatDoesNotExist', [roleName]);
  }
  const permissions = {};
  if (isPermissionControl(rawRoleDef.permissions)) {
    merge(permissions, rawRoleDef.permissions);
  } else {
    for (const permRef of rawRoleDef.permissions ?? []) {
      const referencedPerm = controls.permissions?.[permRef];
      if (referencedPerm) {
        merge(permissions, referencedPerm);
      } else {
        throw messages.createError('RoleReferencesPermissionThatDoesNotExist', [roleName, permRef]);
      }
    }
  }
  return { permissions };
}

function buildAllowedPerms(
  rolePermDef?: PermissionControlSection,
  permClassifications?: PermissionClassifications,
  allowedClassifications?: string[]
): UserRolePermissions {
  const allowedPerms = new Set<string>();
  if (allowedClassifications && permClassifications) {
    for (const [permName, permDef] of Object.entries(permClassifications)) {
      if (allowedClassifications.includes(permDef.classification)) {
        allowedPerms.add(permName);
      }
    }
  }
  if (!rolePermDef) {
    return { allowed: allowedPerms, denied: new Set<string>() };
  }
  if (rolePermDef.allowed) {
    for (const permName of rolePermDef.allowed) {
      allowedPerms.add(permName);
    }
  }
  if (rolePermDef.required) {
    for (const permName of rolePermDef.required) {
      allowedPerms.add(permName);
    }
  }
  if (rolePermDef.denied) {
    for (const permName of rolePermDef.denied) {
      allowedPerms.delete(permName);
    }
  }
  return {
    allowed: allowedPerms,
    denied: new Set<string>(rolePermDef.denied ? rolePermDef.denied.map((p) => p.toLowerCase()) : []),
  };
}
