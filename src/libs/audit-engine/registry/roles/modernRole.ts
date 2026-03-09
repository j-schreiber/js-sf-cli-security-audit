import { RoleDefinitions } from '../shape/schema.js';
import { IUserRole, NamedPermissionClassification, UserRoleCompareResult } from './roleManager.types.js';

/**
 * Next-gen role that uses an extensible configuration to determine
 * allowed permissions (and more) for the role.
 */
export default class ModernRole implements IUserRole {
  public constructor(public roleName: string, private roleDefinition: RoleDefinitions['string']) {}

  public isAllowed(permission: Partial<NamedPermissionClassification>): boolean {
    if (permission.name && this.roleDefinition.deniedPermissions) {
      if (this.roleDefinition.deniedPermissions.includes(permission.name)) {
        return false;
      }
    }
    if (permission.name && this.roleDefinition.allowedPermissions) {
      if (this.roleDefinition.allowedPermissions.includes(permission.name)) {
        return true;
      }
    }
    if (permission.classification && this.roleDefinition.allowedClassifications) {
      return this.roleDefinition.allowedClassifications.includes(permission.classification);
    }
    return false;
  }

  public compareWith(otherRole: IUserRole): UserRoleCompareResult {
    let isSuperset = true;
    if (!this.isModernRole(otherRole)) {
      return { isSuperset: false };
    }
    const otherDef = otherRole.roleDefinition;
    if (this.roleDefinition.allowedClassifications && otherDef.allowedClassifications) {
      for (const allowedClass of otherDef.allowedClassifications) {
        if (!this.roleDefinition.allowedClassifications.includes(allowedClass)) {
          isSuperset = false;
          break;
        }
      }
    } else if (!this.roleDefinition.allowedClassifications && otherDef.allowedClassifications) {
      isSuperset = false;
    }
    if (this.roleDefinition.allowedPermissions && otherDef.allowedPermissions) {
      for (const allowedPerm of otherDef.allowedPermissions) {
        if (!this.roleDefinition.allowedPermissions.includes(allowedPerm)) {
          isSuperset = false;
          break;
        }
      }
    } else if (otherDef.allowedPermissions && !this.roleDefinition.allowedPermissions) {
      isSuperset = false;
    }
    if (this.roleDefinition.deniedPermissions && otherDef.deniedPermissions) {
      for (const deniedPerm of this.roleDefinition.deniedPermissions) {
        if (!otherDef.deniedPermissions.includes(deniedPerm)) {
          isSuperset = false;
          break;
        }
      }
    } else if (this.roleDefinition.deniedPermissions && !otherDef.deniedPermissions) {
      isSuperset = false;
    }
    return { isSuperset };
  }

  // eslint-disable-next-line class-methods-use-this
  private isModernRole(cls: unknown): cls is ModernRole {
    return (cls as ModernRole).roleDefinition !== undefined;
  }
}
