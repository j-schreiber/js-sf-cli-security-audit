import { PermissionRiskLevel, UserPrivilegeLevel } from '../shape/schema.js';
import { IUserRole, NamedPermissionClassification } from './roleManager.types.js';

/**
 * Applies the old logic that only compares ordinal values
 * of roles and classifications.
 */
export default class LegacyRole implements IUserRole {
  private ordinalValue: number;

  public constructor(public roleName: string) {
    this.ordinalValue = Object.keys(UserPrivilegeLevel).length - resolvePresetOrdinalValue(this.roleName);
  }

  public isAllowed(permission: Partial<NamedPermissionClassification>): boolean {
    if (this.roleName === 'UNKNOWN' || !permission.classification) {
      return false;
    }
    // this works, as long as we are mindful when adding new risk levels and presets
    const invertedPermValue =
      Object.keys(PermissionRiskLevel).length - resolveRiskLevelOrdinalValue(permission.classification);
    return this.ordinalValue >= invertedPermValue;
  }
}

function resolvePresetOrdinalValue(value: string): number {
  return Object.keys(UserPrivilegeLevel).indexOf(value.toUpperCase().replace(' ', '_'));
}

function resolveRiskLevelOrdinalValue(value: string): number {
  return Object.keys(PermissionRiskLevel).indexOf(value.toUpperCase());
}
