import z from 'zod';
import { Messages } from '@salesforce/core';
import { PermissionRiskLevel } from '../classification-types.js';
import { ProfilesRiskPreset } from '../policy-types.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'org.audit.run');

export function throwAsSfError(fileName: string, parseError: z.ZodError, rulePath?: PropertyKey[]): never {
  const issues = parseError.issues.map((zodIssue) => {
    const definitivePath = rulePath ? [...rulePath, ...zodIssue.path] : zodIssue.path;
    return definitivePath.length > 0 ? `${zodIssue.message} in "${definitivePath.join('.')}"` : zodIssue.message;
  });
  throw messages.createError('error.InvalidConfigFileSchema', [fileName, issues.join(', ')]);
}

const PermissionsClassificationSchema = z.object({
  /** UI Label */
  label: z.string().optional(),
  /** An optional description to explain the classification */
  reason: z.string().optional(),
  /** Risk assessment of the permissions */
  classification: z.enum(PermissionRiskLevel),
});

const PermsClassificationsMapSchema = z.record(z.string(), PermissionsClassificationSchema);

const NamedPermissionsClassificationSchema = PermissionsClassificationSchema.extend({
  /** Developer name of the permission, used in metadata */
  name: z.string(),
});

const PolicyRuleConfigSchema = z.object({
  enabled: z.boolean().default(true),
  options: z.unknown().optional(),
});

const RuleMapSchema = z.record(z.string(), PolicyRuleConfigSchema);

const PermSetConfig = z.object({
  preset: z.enum(ProfilesRiskPreset),
});

const PermSetMap = z.record(z.string(), PermSetConfig);

const UserConfig = z.object({ role: z.enum(ProfilesRiskPreset) });

const UsersMap = z.record(z.string(), UserConfig);

export const UsersPolicyConfig = z.strictObject({
  defaultRoleForMissingUsers: z.enum(ProfilesRiskPreset).default(ProfilesRiskPreset.STANDARD_USER),
  analyseLastNDaysOfLoginHistory: z.number().optional(),
});

export const NoInactiveUsersOptionsSchema = z.strictObject({
  daysAfterUserIsInactive: z.number().default(90),
});

// FILE CONTENT SCHEMATA

export const PolicyFileSchema = z.object({
  enabled: z.boolean().default(true),
  rules: RuleMapSchema.default({}),
});

export const ProfilesPolicyFileSchema = PolicyFileSchema.extend({
  profiles: PermSetMap,
});

export const PermSetsPolicyFileSchema = PolicyFileSchema.extend({
  permissionSets: PermSetMap,
});

export const PermissionsConfigFileSchema = z.object({
  permissions: z.record(z.string(), PermissionsClassificationSchema),
});

export const UsersPolicyFileSchema = PolicyFileSchema.extend({
  users: UsersMap,
  options: UsersPolicyConfig,
});

// EXPORTED TYPES

// low-level elements
export type PermissionsClassification = z.infer<typeof PermissionsClassificationSchema>;
export type NamedPermissionsClassification = z.infer<typeof NamedPermissionsClassificationSchema>;
export type PermsClassificationsMap = z.infer<typeof PermsClassificationsMapSchema>;
export type PermissionsConfig = z.infer<typeof PermissionsConfigFileSchema>;
export type NoInactiveUsersOptions = z.infer<typeof NoInactiveUsersOptionsSchema>;

// Policies
export type PolicyRuleConfig = z.infer<typeof PolicyRuleConfigSchema>;
export type BasePolicyFileContent = z.infer<typeof PolicyFileSchema>;
export type ProfilesPolicyFileContent = z.infer<typeof ProfilesPolicyFileSchema>;
export type PermSetsPolicyFileContent = z.infer<typeof PermSetsPolicyFileSchema>;
export type UsersPolicyFileContent = z.infer<typeof UsersPolicyFileSchema>;

// Utility types
export type PermissionSetConfig = z.infer<typeof PermSetConfig>;
export type PermissionSetLikeMap = z.infer<typeof PermSetMap>;
export type RuleMap = z.infer<typeof RuleMapSchema>;

// AUDIT CONFIG TYPE

export type ConfigFile<T> = {
  filePath?: string;
  content: T;
};

export type AuditRunConfigClassifications = {
  userPermissions?: ConfigFile<PermissionsConfig>;
  customPermissions?: ConfigFile<PermissionsConfig>;
};

export type AuditRunConfigPolicies = {
  profiles?: ConfigFile<ProfilesPolicyFileContent>;
  permissionSets?: ConfigFile<PermSetsPolicyFileContent>;
  connectedApps?: ConfigFile<BasePolicyFileContent>;
  users?: ConfigFile<UsersPolicyFileContent>;
};

export type AuditRunConfig = {
  classifications: AuditRunConfigClassifications;
  policies: AuditRunConfigPolicies;
};

export function isPermissionsConfig(cls: unknown): cls is ConfigFile<PermissionsConfig> {
  return (cls as ConfigFile<PermissionsConfig>).content?.permissions !== undefined;
}

export function isPolicyConfig(cls: unknown): cls is ConfigFile<BasePolicyFileContent> {
  return (cls as ConfigFile<BasePolicyFileContent>).content?.rules !== undefined;
}
