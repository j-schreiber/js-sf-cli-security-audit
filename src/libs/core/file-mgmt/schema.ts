import z from 'zod';
import { Messages } from '@salesforce/core';
import { PermissionRiskLevel } from '../classification-types.js';
import { UserPrivilegeLevel } from '../policy-types.js';

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
  role: z.enum(UserPrivilegeLevel),
});

const PermSetMap = z.record(z.string(), PermSetConfig);

const ProfilesMap = z.record(z.string(), PermSetConfig);

const UserConfig = z.object({ role: z.enum(UserPrivilegeLevel) });

const UsersMap = z.record(z.string(), UserConfig);

export const UsersPolicyConfig = z.strictObject({
  defaultRoleForMissingUsers: z.enum(UserPrivilegeLevel).default(UserPrivilegeLevel.STANDARD_USER),
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

export const PermissionsClassificationFileSchema = z.object({
  permissions: z.record(z.string(), PermissionsClassificationSchema),
});

export const UsersPolicyFileSchema = PolicyFileSchema.extend({
  options: UsersPolicyConfig,
});

export const ProfilesClassificationContentSchema = z.object({
  profiles: ProfilesMap,
});

export const PermissionSetsClassificationContentSchema = z.object({
  permissionSets: PermSetMap,
});

export const UsersClassificationContentSchema = z.object({
  users: UsersMap,
});

// EXPORTED TYPES

// low-level elements
export type PermissionClassification = z.infer<typeof PermissionsClassificationSchema>;
export type NamedPermissionClassification = z.infer<typeof NamedPermissionsClassificationSchema>;
export type NoInactiveUsersOptions = z.infer<typeof NoInactiveUsersOptionsSchema>;

// Policies
export type PolicyRuleConfig = z.infer<typeof PolicyRuleConfigSchema>;
export type BasePolicyFileContent = z.infer<typeof PolicyFileSchema>;
export type ProfilesPolicyFileContent = z.infer<typeof ProfilesPolicyFileSchema>;
export type PermSetsPolicyFileContent = z.infer<typeof PermSetsPolicyFileSchema>;
export type UsersPolicyFileContent = z.infer<typeof UsersPolicyFileSchema>;

// Classifications
export type PermissionsClassificationContent = z.infer<typeof PermissionsClassificationFileSchema>;
export type ProfilesClassificationContent = z.infer<typeof ProfilesClassificationContentSchema>;
export type PermissionSetsClassificationContent = z.infer<typeof PermissionSetsClassificationContentSchema>;
export type UsersClassificationContent = z.infer<typeof UsersClassificationContentSchema>;

// Utility types
export type PermissionSetConfig = z.infer<typeof PermSetConfig>;
export type RuleMap = z.infer<typeof RuleMapSchema>;
export type ProfilesMap = z.infer<typeof ProfilesMap>;
export type PermissionSetsMap = z.infer<typeof PermSetMap>;
export type UserConfig = z.infer<typeof UserConfig>;

// AUDIT CONFIG TYPE

export type ConfigFile<T> = {
  filePath?: string;
  content: T;
};

type ClassificationsFile = {
  [key: string]: Record<string, unknown>;
};

export type AuditRunConfigClassifications = {
  userPermissions?: ConfigFile<PermissionsClassificationContent>;
  customPermissions?: ConfigFile<PermissionsClassificationContent>;
  profiles?: ConfigFile<ProfilesClassificationContent>;
  permissionSets?: ConfigFile<PermissionSetsClassificationContent>;
  users?: ConfigFile<UsersClassificationContent>;
};

type ExtractRecordFromConfigFile<C> = C extends ConfigFile<infer T> ? T[keyof T] : never;

/**
 * Utility type to extract the actual mapped entities from audit run classifications
 */
export type ExtractedClassifications = {
  [K in keyof AuditRunConfigClassifications]: ExtractRecordFromConfigFile<AuditRunConfigClassifications[K]>;
};

export function extractEntities<C extends ConfigFile<ClassificationsFile>>(config: C): ExtractRecordFromConfigFile<C> {
  const value = Object.values(config.content)[0];
  return value as ExtractRecordFromConfigFile<C>;
}

export type Classifications = keyof AuditRunConfigClassifications;

export type AuditRunConfigPolicies = {
  profiles?: ConfigFile<BasePolicyFileContent>;
  permissionSets?: ConfigFile<BasePolicyFileContent>;
  connectedApps?: ConfigFile<BasePolicyFileContent>;
  settings?: ConfigFile<BasePolicyFileContent>;
  users?: ConfigFile<UsersPolicyFileContent>;
};

export type AuditRunConfig = {
  classifications: AuditRunConfigClassifications;
  policies: AuditRunConfigPolicies;
};

export function isPermissionsClassification(cls: unknown): cls is ConfigFile<PermissionsClassificationContent> {
  return (cls as ConfigFile<PermissionsClassificationContent>).content?.permissions !== undefined;
}

export function isPolicyConfig(cls: unknown): cls is ConfigFile<BasePolicyFileContent> {
  return (cls as ConfigFile<BasePolicyFileContent>).content?.rules !== undefined;
}
