import z from 'zod';
import { PermissionRiskLevel } from '../classification-types.js';
import { ProfilesRiskPreset } from '../policy-types.js';

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
  config: z.unknown().optional(),
});

const RuleMapSchema = z.record(z.string(), PolicyRuleConfigSchema);

const PermSetConfig = z.object({
  preset: z.enum(ProfilesRiskPreset),
});

const PermSetMap = z.record(z.string(), PermSetConfig);

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

// EXPORTED TYPES

export type PermissionsClassification = z.infer<typeof PermissionsClassificationSchema>;
export type NamedPermissionsClassification = z.infer<typeof NamedPermissionsClassificationSchema>;
export type PermsClassificationsMap = z.infer<typeof PermsClassificationsMapSchema>;
export type PermissionsConfig = z.infer<typeof PermissionsConfigFileSchema>;
export type PolicyRuleConfig = z.infer<typeof PolicyRuleConfigSchema>;
export type BasePolicyFileContent = z.infer<typeof PolicyFileSchema>;
export type ProfilesPolicyFileContent = z.infer<typeof ProfilesPolicyFileSchema>;
export type PermSetsPolicyFileContent = z.infer<typeof PermSetsPolicyFileSchema>;
export type PermissionSetConfig = z.infer<typeof PermSetConfig>;
export type PermissionSetLikeMap = z.infer<typeof PermSetMap>;
export type RuleMap = z.infer<typeof RuleMapSchema>;

// AUDIT CONFIG TYPE

export type ConfigFile<T> = {
  filePath?: string;
  content: T;
};

export type AuditRunConfigClassifications = {
  [classificationName: string]: unknown;
  userPermissions?: ConfigFile<PermissionsConfig>;
  customPermissions?: ConfigFile<PermissionsConfig>;
};

export type AuditRunConfigPolicies = {
  [policyName: string]: unknown;
  Profiles?: ConfigFile<ProfilesPolicyFileContent>;
  PermissionSets?: ConfigFile<PermSetsPolicyFileContent>;
  ConnectedApps?: ConfigFile<BasePolicyFileContent>;
};

export type AuditRunConfig = {
  [configType: string]: unknown;
  classifications: AuditRunConfigClassifications;
  policies: AuditRunConfigPolicies;
};

export function isPermissionsConfig(cls: unknown): cls is ConfigFile<PermissionsConfig> {
  return (cls as ConfigFile<PermissionsConfig>).content?.permissions !== undefined;
}

export function isPolicyConfig(cls: unknown): cls is ConfigFile<BasePolicyFileContent> {
  return (cls as ConfigFile<BasePolicyFileContent>).content?.rules !== undefined;
}
