import z from 'zod';
import { PermissionRiskLevelPresets, PolicyRiskLevel } from './types.js';

const PermissionsClassificationSchema = z.object({
  /** UI Label */
  label: z.string().optional(),
  /** An optional description to explain the classification */
  reason: z.string().optional(),
  /** Risk assessment of the permissions */
  classification: z.enum(PolicyRiskLevel),
});

const NamedPermissionsClassificationSchema = PermissionsClassificationSchema.extend({
  /** Developer name of the permission, used in metadata */
  name: z.string(),
});

const PolicyRuleConfigSchema = z.object({
  enabled: z.boolean().default(true),
  config: z.unknown().optional(),
});

export const PolicyConfigSchema = z.object({
  enabled: z.boolean().default(true),
  rules: z.record(z.string(), PolicyRuleConfigSchema),
});

const PermSetConfig = z.object({
  preset: z.enum(PermissionRiskLevelPresets),
});

const PermSetMap = z.record(z.string(), PermSetConfig);

export const ProfilesPolicyConfigSchema = PolicyConfigSchema.extend({
  profiles: PermSetMap,
});

export const PermSetsPolicyConfigSchema = PolicyConfigSchema.extend({
  permissionSets: PermSetMap,
});

export const PermissionsConfigSchema = z.object({
  permissions: z.record(z.string(), PermissionsClassificationSchema),
});

export type PermissionsClassification = z.infer<typeof PermissionsClassificationSchema>;
export type NamedPermissionsClassification = z.infer<typeof NamedPermissionsClassificationSchema>;
export type PermissionsConfig = z.infer<typeof PermissionsConfigSchema>;
export type PolicyRuleConfig = z.infer<typeof PolicyRuleConfigSchema>;
export type PolicyConfig = z.infer<typeof PolicyConfigSchema>;
export type ProfilesPolicyConfig = z.infer<typeof ProfilesPolicyConfigSchema>;
export type PermSetsPolicyConfig = z.infer<typeof PermSetsPolicyConfigSchema>;
export type PermissionSetConfig = z.infer<typeof PermSetConfig>;
export type PermissionSetLikeMap = z.infer<typeof PermSetMap>;
