import z from 'zod';
import { PolicyRiskLevel } from './types.js';

const PermissionsClassificationSchema = z.object({
  /** API name of the permission. Used in profile metadata or SOQL */
  name: z.string(),
  /** UI Label */
  label: z.string().optional(),
  /** An optional description to explain the classification */
  reason: z.string().optional(),
  /** Risk assessment of the permissions */
  classification: z.enum(PolicyRiskLevel),
});

const PolicyRuleConfigSchema = z.object({ enabled: z.boolean().default(true) });

const PolicyConfigSchema = z.object({
  enabled: z.boolean().default(true),
  rules: z.record(z.string(), PolicyRuleConfigSchema),
});

const ProfileConfig = z.object({
  preset: z.string(),
  enforceIpRanges: z.boolean().optional(),
});

const ProfilesPolicyConfigSchema = PolicyConfigSchema.extend({
  profiles: z.record(z.string(), ProfileConfig),
});

const PermissionsConfigSchema = z.object({
  permissions: z.record(
    z.string(),
    z.object({ label: z.string().optional(), reason: z.string().optional(), classification: z.enum(PolicyRiskLevel) })
  ),
});

export type PermissionsClassification = z.infer<typeof PermissionsClassificationSchema>;
export type PermissionsConfig = z.infer<typeof PermissionsConfigSchema>;
export type PolicyRuleConfig = z.infer<typeof PolicyRuleConfigSchema>;
export type PolicyConfig = z.infer<typeof PolicyConfigSchema>;
export type ProfilesPolicyConfig = z.infer<typeof ProfilesPolicyConfigSchema>;
