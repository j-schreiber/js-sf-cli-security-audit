import { ParsedAuditConfig } from '../../file-manager/fileManager.types.js';
import {
  PermissionsClassificationFileSchema,
  PermissionSetsClassificationFileSchema,
  PolicyFileSchema,
  ProfilesClassificationFileSchema,
  UserClassificationFileSchema,
  UserPolicyFileSchema,
} from './schema.js';

export type AuditRunConfig = ParsedAuditConfig<typeof AuditConfigShape>;
export type Policies = keyof (typeof AuditConfigShape)['policies'];
export type PolicyShapes = AuditRunConfig['policies'];
export type Classifications = keyof (typeof AuditConfigShape)['classifications'];
export type ClassificationShapes = AuditRunConfig['classifications'];

/**
 * The shape defines the directory structure and schema files to
 * parse YAML files. It is the foundation to derive the runtime type of
 * the audit config that is used by rules and policies.
 */
export const AuditConfigShape = {
  classifications: {
    userPermissions: {
      schema: PermissionsClassificationFileSchema,
      entities: 'permissions',
    },
    customPermissions: {
      schema: PermissionsClassificationFileSchema,
      entities: 'permissions',
    },
    profiles: {
      schema: ProfilesClassificationFileSchema,
      entities: 'profiles',
    },
    permissionSets: {
      schema: PermissionSetsClassificationFileSchema,
      entities: 'permissionSets',
    },
    users: {
      schema: UserClassificationFileSchema,
      entities: 'users',
    },
  },
  policies: {
    profiles: {
      schema: PolicyFileSchema,
      dependencies: [
        { path: ['classifications', 'userPermissions'], errorName: 'UserPermClassificationRequiredForProfiles' },
      ],
    },
    permissionSets: {
      schema: PolicyFileSchema,
      dependencies: [
        { path: ['classifications', 'userPermissions'], errorName: 'UserPermClassificationRequiredForPermSets' },
      ],
    },
    connectedApps: {
      schema: PolicyFileSchema,
    },
    users: {
      schema: UserPolicyFileSchema,
    },
    settings: {
      schema: PolicyFileSchema,
    },
  },
};
