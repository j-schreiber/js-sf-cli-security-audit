import { NamedPermissionsClassification } from './file-mgmt/schema.js';

/**
 * Enum to classify user and custom permissions.
 */
export enum PermissionRiskLevel {
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

export function resolveRiskLevelOrdinalValue(value: string): number {
  return Object.keys(PermissionRiskLevel).indexOf(value.toUpperCase());
}

export const classificationSorter = (a: NamedPermissionsClassification, b: NamedPermissionsClassification): number =>
  resolveRiskLevelOrdinalValue(a.classification) - resolveRiskLevelOrdinalValue(b.classification);
