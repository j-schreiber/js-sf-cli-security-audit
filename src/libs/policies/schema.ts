import z from 'zod';
import { PolicyRiskLevel } from './types.js';

const PermissionsPolicySchema = z.object({
  /** API name of the permission. Used in profile metadata or SOQL */
  name: z.string(),
  /** UI Label */
  label: z.string().optional(),
  /** An optional description to explain the classification */
  reason: z.string().optional(),
  /** Risk assessment of the permissions */
  classification: z.enum(PolicyRiskLevel),
});

const PermissionsConfigSchema = z.object({
  permissions: z.record(
    z.string(),
    z.object({ label: z.string().optional(), reason: z.string().optional(), classification: z.enum(PolicyRiskLevel) })
  ),
});

export type PermissionsPolicy = z.infer<typeof PermissionsPolicySchema>;
export type PermissionsConfig = z.infer<typeof PermissionsConfigSchema>;
