import z from 'zod';
import { AuditConfigShape } from '../audit-engine/index.js';

type Shapes = (typeof AuditConfigShape)['shape']['files'];
type Inventories = (typeof AuditConfigShape)['inventory']['files'];

export type PermissionClassifications = z.infer<Shapes['userPermissions']['schema']>;
export type NamedPermissionClassification = PermissionClassifications['string'] & { name: string };
export type UnclassifiedPerm = Omit<NamedPermissionClassification, 'classification'>;
export type ProfileClassifications = z.infer<Inventories['profiles']['schema']>;
export type PermsetClassifications = z.infer<Inventories['permissionSets']['schema']>;
export type UserClassifications = z.infer<Inventories['users']['schema']>;

export enum AuditInitPresets {
  strict = 'strict',
  loose = 'loose',
  none = 'none',
}

export type Preset = {
  classifyUserPermissions(rawPerms: UnclassifiedPerm[]): NamedPermissionClassification[];
};
