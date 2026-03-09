import { RoleDefinitions } from '../shape/schema.js';
import { IUserRole, NamedPermissionClassification } from './roleManager.types.js';

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
}
