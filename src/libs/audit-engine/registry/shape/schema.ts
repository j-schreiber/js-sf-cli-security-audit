import z from 'zod';

const IP4RegExp = /^(((?!25?[6-9])[12]\d|[1-9])?\d\.?\b){4}$/;

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
  /** Not categorized or unknown permission. Will be ignored but create a warning */
  UNKNOWN = 'Unknown',
}

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

const PermClassification = z.object({
  /** UI Label */
  label: z.string().optional(),
  /** An optional description to explain the classification */
  reason: z.string().optional(),
  /** Risk assessment of the permissions */
  classification: z.enum(PermissionRiskLevel),
});

const PermissionClassifications = z.record(z.string(), PermClassification);

const PolicyRuleConfigSchema = z.object({
  enabled: z.boolean().default(false),
  options: z.record(z.string(), z.unknown()).optional(),
});

const RuleMapSchema = z.record(z.string(), PolicyRuleConfigSchema);

const PermSetConfig = z.strictObject({
  role: z.enum(UserPrivilegeLevel),
});

const ProfileConfig = PermSetConfig.extend({
  allowedLoginIps: z.array(z.object({ from: z.string().regex(IP4RegExp), to: z.string().regex(IP4RegExp) })).optional(),
});

const PermSetMap = z.record(z.string(), PermSetConfig);

const ProfilesMap = z.record(z.string(), ProfileConfig);

const UserConfig = z.object({ role: z.enum(UserPrivilegeLevel) });

const UsersMap = z.record(z.string(), UserConfig);

const UsersPolicyOptions = z.strictObject({
  defaultRoleForMissingUsers: z.enum(UserPrivilegeLevel).default(UserPrivilegeLevel.STANDARD_USER),
  analyseLastNDaysOfLoginHistory: z.number().optional(),
});

// Classification File Schemata

export const PermissionsClassificationFileSchema = z.object({
  permissions: PermissionClassifications,
});

export const ProfilesClassificationFileSchema = z.object({
  profiles: ProfilesMap,
});

export const PermissionSetsClassificationFileSchema = z.object({
  permissionSets: PermSetMap,
});

export const UserClassificationFileSchema = z.object({
  users: UsersMap,
});

// Policy File Schemata

export const PolicyFileSchema = z.object({
  enabled: z.boolean().default(true),
  rules: RuleMapSchema.default({}),
  options: z.record(z.string(), z.unknown()).optional(),
});

export const UserPolicyFileSchema = PolicyFileSchema.extend({
  options: UsersPolicyOptions,
});

// Accepted Risks Schemata

// Recursive schema type; same as accepted risks "TreeNode | BranchNode"
// must be exported because otherwise yarn compile fails
export type NestedStructure = {
  [key: string]: NestedStructure | { reason: string };
};

const allowedRiskSchema = z.object({ reason: z.string() });

/**
 * z.lazy allows to define a recursive schema that can be a a accepted
 * risk or a structure of nested identifiers.
 */
const mappingOrAllowedRisk: z.ZodType<NestedStructure> = z.lazy(() =>
  z.record(z.string(), z.union([allowedRiskSchema, mappingOrAllowedRisk]))
);

export const AcceptedRisksSchema = z.record(z.string(), mappingOrAllowedRisk);

// Classification Types
export type PermissionClassifications = z.infer<typeof PermissionClassifications>;
export type PermissionSetClassifications = z.infer<typeof PermSetMap>;
export type ProfileClassifications = z.infer<typeof ProfilesMap>;
export type UserClassifications = z.infer<typeof UsersMap>;

// Policy Types
export type PolicyConfig = z.infer<typeof PolicyFileSchema>;
export type UserPolicyConfig = z.infer<typeof UserPolicyFileSchema>;

// Accepted Risks
export type AcceptedRuleRisks = z.infer<typeof AcceptedRisksSchema>;
