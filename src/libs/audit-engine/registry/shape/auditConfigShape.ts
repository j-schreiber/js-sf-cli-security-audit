import {
  ComposableRolesFileSchema,
  PermissionControlsFileSchema,
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
  controls: {
    files: {
      roles: { schema: ComposableRolesFileSchema },
      permissions: { schema: PermissionControlsFileSchema },
    },
  },
  shape: {
    files: {
      userPermissions: { schema: PermissionsClassificationFileSchema, isCountable: true },
      customPermissions: { schema: PermissionsClassificationFileSchema, isCountable: true },
    },
  },
  inventory: {
    files: {
      profiles: { schema: ProfilesClassificationFileSchema, isCountable: true },
      permissionSets: { schema: PermissionSetsClassificationFileSchema, isCountable: true },
      users: { schema: UserClassificationFileSchema, isCountable: true },
    },
  },
  policies: {
    files: {
      profiles: {
        schema: PolicyFileSchema,
        dependencies: [{ path: ['shape', 'userPermissions'], errorName: 'UserPermClassificationRequiredForProfiles' }],
        isCountable: true,
        entities: 'rules',
      },
      permissionSets: {
        schema: PolicyFileSchema,
        dependencies: [{ path: ['shape', 'userPermissions'], errorName: 'UserPermClassificationRequiredForPermSets' }],
        isCountable: true,
        entities: 'rules',
      },
      connectedApps: {
        schema: PolicyFileSchema,
        isCountable: true,
        entities: 'rules',
      },
      users: {
        schema: UserPolicyFileSchema,
        isCountable: true,
        entities: 'rules',
      },
      settings: {
        schema: PolicyFileSchema,
        isCountable: true,
        entities: 'rules',
      },
    },
  },
};
