import z from 'zod';
import {
  PermissionsConfigFileSchema,
  PermSetsPolicyFileSchema,
  PolicyFileSchema,
  ProfilesPolicyFileSchema,
  UsersPolicyFileSchema,
} from './file-mgmt/schema.js';
import { Constructor } from './registries/types.js';
import ConnectedAppPolicy from './policies/connectedAppPolicy.js';
import PermissionSetPolicy from './policies/permissionSetPolicy.js';
import Policy from './policies/policy.js';
import ProfilePolicy from './policies/profilePolicy.js';
import UserPolicy from './policies/userPolicy.js';

export const classificationDefs: ClassificationRegistry = {
  userPermissions: {
    schema: PermissionsConfigFileSchema,
  },
  customPermissions: {
    schema: PermissionsConfigFileSchema,
  },
};

export const policyDefs: PolicyRegistry = {
  Profiles: {
    handler: ProfilePolicy,
    fileName: 'profiles',
    schema: ProfilesPolicyFileSchema,
    dependencies: [
      { path: ['classifications', 'userPermissions'], errorName: 'UserPermClassificationRequiredForProfiles' },
    ],
  },
  PermissionSets: {
    handler: PermissionSetPolicy,
    fileName: 'permissionSets',
    schema: PermSetsPolicyFileSchema,
    dependencies: [
      { path: ['classifications', 'userPermissions'], errorName: 'UserPermClassificationRequiredForPermSets' },
    ],
  },
  ConnectedApps: {
    handler: ConnectedAppPolicy,
    fileName: 'connectedApps',
    schema: PolicyFileSchema,
  },
  Users: {
    handler: UserPolicy,
    fileName: 'users',
    schema: UsersPolicyFileSchema,
  },
};

type PolicyRegistryEntry = ConfigFileDefinition & {
  dependencies?: ConfigFileDependency[];
  handler: Constructor<Policy<unknown>>;
};

type ConfigFileDefinition = {
  fileName?: string;
  schema: z.ZodObject;
};

type ConfigFileDependency = {
  errorName: string;
  path: string[];
};

type PolicyRegistry = {
  [policyName: string]: PolicyRegistryEntry;
};

type ClassificationRegistry = {
  [classificationName: string]: ConfigFileDefinition;
};
