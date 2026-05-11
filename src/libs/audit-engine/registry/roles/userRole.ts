import { merge } from '@salesforce/kit';
import { Messages } from '@salesforce/core';
import {
  PermissionClassifications,
  PermissionRiskLevel,
  UserPrivilegeLevel,
  isPermissionControl,
  PermissionControlSection,
  ObjectAccessControl,
  isObjectAccessControl,
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

type DefinitiveObjectAccessDef = Required<ObjectAccessControl['string']>;

type UserRoleConfig = {
  userPermissions: UserRolePermissions;
  customPermissions: UserRolePermissions;
  objectAccess: ObjectAccessControl;
  roleOrdinalValue?: number;
  isStrict: boolean;
};

export default class UserRole {
  private config: UserRoleConfig;
  private objectAccess: Record<string, DefinitiveObjectAccessDef>;

  public constructor(public roleName: string, config: Partial<UserRoleConfig>) {
    this.config = {
      userPermissions: { allowed: new Set<string>(), denied: new Set<string>() },
      customPermissions: { allowed: new Set<string>(), denied: new Set<string>() },
      objectAccess: {},
      isStrict: false,
      ...config,
    };
    this.objectAccess = {};
    for (const [objName, objDef] of Object.entries(config.objectAccess ?? {})) {
      this.objectAccess[objName] = {
        allowRead: false,
        allowCreate: false,
        allowDelete: false,
        allowEdit: false,
        ...objDef,
      };
    }
  }

  /**
   * Evaluates if a permission is explicitly denied
   *
   * @param permission
   * @returns
   */
  public isDenied(permission: TypedPermission): boolean {
    if (permission.type === 'customPermissions') {
      return this.config.customPermissions.denied.has(permission.name.toLowerCase());
    } else {
      return this.config.userPermissions.denied.has(permission.name.toLowerCase());
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
      return this.config.customPermissions.allowed.has(permission.name);
    } else {
      return this.config.userPermissions.allowed.has(permission.name);
    }
  }

  /**
   * Runs a deep analysis of all access controls (permissions, object access, etc)
   * of the role and determins which role is more permissive (or if they are intersecting)
   *
   * @param otherRole
   * @returns
   */
  public compareWith(otherRole: UserRole): UserRoleCompareResult {
    const missingPermsInOther = new Array<string>();
    const missingPermsInThis = new Array<string>();
    const isOrdinallyHigher =
      this.config.roleOrdinalValue && otherRole.config.roleOrdinalValue
        ? this.config.roleOrdinalValue >= otherRole.config.roleOrdinalValue
        : true;
    const merged = new Set([...this.config.userPermissions.allowed, ...otherRole.config.userPermissions.allowed]);
    for (const perm of merged) {
      if (!this.config.userPermissions.allowed.has(perm)) {
        missingPermsInThis.push(perm);
      }
      if (!otherRole.config.userPermissions.allowed.has(perm)) {
        missingPermsInOther.push(perm);
      }
    }
    return {
      isSuperset: missingPermsInThis.length === 0 && isOrdinallyHigher,
      missingPermsInThis,
      missingPermsInOther,
    };
  }

  public allowsObjectAccess(objName: string, accessType: keyof DefinitiveObjectAccessDef): boolean {
    const allowedObjectAccess = this.config.objectAccess[objName];
    // if object is not explicitly defined, we allow access for roles that are "not strict"
    if (!allowedObjectAccess) {
      return !this.config.isStrict;
    }
    return allowedObjectAccess[accessType] ?? false;
  }
}

export function newRoleFromDefinition(roleName: string, config: RoleManagerConfig): UserRole {
  const { permissions, objectAccess, strict } = resolveRole(roleName, config.controls);
  const userPermissions = buildAllowedPerms(
    permissions?.userPermissions,
    config.shape.userPermissions,
    permissions?.allowedClassifications
  );
  const customPermissions = buildAllowedPerms(
    permissions?.customPermissions,
    config.shape.customPermissions,
    permissions?.allowedClassifications
  );
  return new UserRole(roleName, { userPermissions, customPermissions, objectAccess, isStrict: strict });
}

export function newRoleFromOrdinals(roleName: UserPrivilegeLevel, perms?: PermissionClassifications): UserRole {
  const roleOrdinalValue = resolvePresetOrdinalValue(roleName);
  if (!perms || roleName === UserPrivilegeLevel.UNKNOWN) {
    return new UserRole(roleName, {
      userPermissions: { allowed: new Set<string>(), denied: new Set<string>() },
      customPermissions: { allowed: new Set<string>(), denied: new Set<string>() },
      roleOrdinalValue,
      objectAccess: {},
    });
  }
  const allAllowed = new Set<string>();
  for (const [permName, permDef] of Object.entries(perms)) {
    if (roleOrdinalValue >= resolveRiskLevelOrdinalValue(permDef.classification)) {
      allAllowed.add(permName);
    }
  }
  return new UserRole(roleName, {
    userPermissions: { allowed: allAllowed, denied: new Set<string>() },
    customPermissions: { allowed: new Set<string>(), denied: new Set<string>() },
    roleOrdinalValue,
    objectAccess: {},
  });
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
  const objectAccess: ObjectAccessControl = {};
  if (isObjectAccessControl(rawRoleDef.objectAccess)) {
    merge(objectAccess, rawRoleDef.objectAccess);
  } else {
    for (const objRef of rawRoleDef.objectAccess ?? []) {
      const referencedObjDef = controls.objectAccess?.[objRef];
      if (referencedObjDef) {
        merge(objectAccess, referencedObjDef);
      } else {
        throw messages.createError('RoleReferencesPermissionThatDoesNotExist', [roleName, objRef]);
      }
    }
  }
  return { permissions, objectAccess, strict: rawRoleDef.strict ?? false };
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
