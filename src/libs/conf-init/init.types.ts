import z from 'zod';
import { AuditConfigShape } from '../audit-engine/index.js';

type AuditClassifications = (typeof AuditConfigShape)['classifications']['files'];

export type PermissionClassifications = z.infer<AuditClassifications['userPermissions']['schema']>;
export type NamedPermissionClassification = PermissionClassifications['permissions']['string'] & { name: string };
export type UnclassifiedPerm = Omit<NamedPermissionClassification, 'classification'>;
export type ProfileClassifications = z.infer<AuditClassifications['profiles']['schema']>;
export type PermsetClassifications = z.infer<AuditClassifications['permissionSets']['schema']>;
export type UserClassifications = z.infer<AuditClassifications['users']['schema']>;

export enum AuditInitPresets {
  strict = 'strict',
  loose = 'loose',
  none = 'none',
}

export type Preset = {
  classifyUserPermissions(rawPerms: UnclassifiedPerm[]): NamedPermissionClassification[];
};
