import {
  PermissionsClassificationFileSchema,
  PermissionSetsClassificationFileSchema,
  PolicyFileSchema,
  ProfilesClassificationFileSchema,
  UserClassificationFileSchema,
  UserPolicyFileSchema,
} from './schema.js';

/**
 * The shape defines the directory structure and schema files to
 * parse YAML files. It is the foundation to derive the runtime type of
 * the audit config that is used by rules and policies.
 */
export const BaseAuditConfigShape = {
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
};
