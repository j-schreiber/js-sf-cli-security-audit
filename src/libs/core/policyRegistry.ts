import z from 'zod';
import {
  AuditRunConfigClassifications,
  AuditRunConfigPolicies,
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

export type PolicyNames = keyof AuditRunConfigPolicies;
export type ClassificationNames = keyof AuditRunConfigClassifications;

export type PolicyRegistry = Record<PolicyNames, PolicyRegistryEntry>;

export const policyDefs: PolicyRegistry = {
  profiles: {
    handler: ProfilePolicy,
    schema: ProfilesPolicyFileSchema,
    dependencies: [
      { path: ['classifications', 'userPermissions'], errorName: 'UserPermClassificationRequiredForProfiles' },
    ],
  },
  permissionSets: {
    handler: PermissionSetPolicy,
    schema: PermSetsPolicyFileSchema,
    dependencies: [
      { path: ['classifications', 'userPermissions'], errorName: 'UserPermClassificationRequiredForPermSets' },
    ],
  },
  connectedApps: {
    handler: ConnectedAppPolicy,
    schema: PolicyFileSchema,
  },
  users: {
    handler: UserPolicy,
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

type ClassificationRegistry = Record<keyof AuditRunConfigClassifications, ConfigFileDefinition>;
