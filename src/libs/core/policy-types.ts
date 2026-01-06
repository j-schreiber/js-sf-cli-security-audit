import { PermissionRiskLevel, resolveRiskLevelOrdinalValue } from './classification-types.js';

/**
 * Privilege levels are assigned to users, profiles and permission sets.
 * Each level determins the allowed permissions, based on their risk levels.
 */
export enum UserPrivilegeLevel {
  /** Allows up to "Critical" permissions */
  DEVELOPER = 'Developer',
  /** Allows up to "High" permissions */
  ADMIN = 'Admin',
  /** Allows up to "Medium" permissions */
  POWER_USER = 'Power User',
  /** Allows only "Low" permissions */
  STANDARD_USER = 'Standard User',
  /** Disables the profile for audit */
  UNKNOWN = 'Unknown',
}

export function resolvePresetOrdinalValue(value: string): number {
  return Object.keys(UserPrivilegeLevel).indexOf(value.toUpperCase().replace(' ', '_'));
}

export function permissionAllowedInPreset(permClassification: string, preset: string): boolean {
  // this works, as long as we are mindful when adding new risk levels and presets
  const invertedPermValue = Object.keys(PermissionRiskLevel).length - resolveRiskLevelOrdinalValue(permClassification);
  const invertedPresetValue = Object.keys(UserPrivilegeLevel).length - resolvePresetOrdinalValue(preset);
  return invertedPresetValue >= invertedPermValue;
}
