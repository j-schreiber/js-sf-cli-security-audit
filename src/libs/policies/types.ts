export enum PolicyRiskLevel {
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

export type PolicyWriteResult = {
  paths: Record<string, string>;
};
