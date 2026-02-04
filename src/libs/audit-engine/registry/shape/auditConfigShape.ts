import { AuditConfigShapeDefinition, ExtractAuditConfigTypes } from '../../file-manager/fileManager.types.js';
import {
  PermissionsClassificationFileSchema,
  PermissionSetsClassificationFileSchema,
  PolicyFileSchema,
  ProfilesClassificationFileSchema,
  UserClassificationFileSchema,
  UserPolicyFileSchema,
} from './schema.js';

export type AuditRunConfig = ExtractAuditConfigTypes<typeof AuditConfigShape>;
export type Policies = keyof (typeof AuditConfigShape)['policies']['files'];
export type PolicyShapes = AuditRunConfig['policies'];
export type Classifications = keyof (typeof AuditConfigShape)['classifications']['files'];
export type ClassificationShapes = AuditRunConfig['classifications'];

/**
 * The shape defines the directory structure and schema files to
 * parse YAML files. It is the foundation to derive the runtime type of
 * the audit config that is used by rules and policies.
 */
export const AuditConfigShape = {
  classifications: {
    files: {
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
  },
  policies: {
    files: {
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
  },
} satisfies AuditConfigShapeDefinition;
