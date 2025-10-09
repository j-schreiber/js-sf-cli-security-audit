export enum PolicyRiskLevel {
  /** Blacklisted permissions that are considered too critical and not allowed */
  BLOCKED = 'Blocked',
  /** Developer permissions, allow to modify the application */
  CRITICAL = 'Critical',
  /** Admin permissions, allow to manage users and change permissions */
  HIGH = 'High',
  /** Elevated business permissions for privileged users */
  MEDIUM = 'Medium',
  /** Regular user permissions, typically needed for day-to-day work */
  LOW = 'Low',
  /** Not categorized or unknown permission */
  UNKNOWN = 'Unknown',
}

/**
 * Presets can be assigned to profiles and permission sets.
 * A preset allows permissions up to a fixed risk level.
 */
export enum PermissionRiskLevelPresets {
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

export type PolicyWriteResult = {
  paths: Record<string, string>;
};

export function resolveRiskLevelOrdinalValue(value: string): number {
  return Object.keys(PolicyRiskLevel).indexOf(value.toUpperCase());
}

export function resolvePresetOrdinalValue(value: string): number {
  return Object.keys(PermissionRiskLevelPresets).indexOf(value.toUpperCase().replace(' ', '_'));
}
