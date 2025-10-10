import { readFileSync } from 'node:fs';
import path from 'node:path';
import yaml from 'js-yaml';
import z, { ZodObject } from 'zod';
import {
  CUSTOM_PERMISSIONS_PATH,
  PERMSET_POLICY_PATH,
  PROFILE_POLICY_PATH,
  USER_PERMISSIONS_PATH,
} from '../config/filePaths.js';
import {
  PermissionsConfig,
  PermissionsConfigSchema,
  PermSetsPolicyConfigSchema,
  PolicyConfig,
  ProfilesPolicyConfigSchema,
} from './schema.js';

/**
 * Instance of an audit run that executes all high-level operations
 */
export default class AuditRun {
  public configs: AuditRunConfig;

  private constructor(directoryPath: string) {
    this.configs = new AuditRunConfig(directoryPath);
  }

  public static load(directoryPath: string): AuditRun {
    const ps = new AuditRun(directoryPath);
    return ps;
  }
}

/**
 * Holds all parsed and validated configration file contents
 * from a source directory.
 */
export class AuditRunConfig {
  public classifications;
  public policies;

  public constructor(directoryPath: string) {
    this.classifications = new AuditRunClassifications(directoryPath);
    this.policies = new AuditRunPolicies(directoryPath);
  }
}

class AuditRunClassifications {
  public userPermissions: AuditClassificationDef;
  public customPermissions: AuditClassificationDef;

  public constructor(directoryPath: string) {
    this.userPermissions = new AuditClassificationDef(path.join(directoryPath, USER_PERMISSIONS_PATH));
    this.customPermissions = new AuditClassificationDef(path.join(directoryPath, CUSTOM_PERMISSIONS_PATH));
  }
}

class AuditRunPolicies {
  public profiles: AuditPolicyDef<z.infer<typeof ProfilesPolicyConfigSchema>>;
  public permissionSets: AuditPolicyDef<z.infer<typeof PermSetsPolicyConfigSchema>>;

  public constructor(directoryPath: string) {
    this.profiles = new AuditPolicyDef(path.join(directoryPath, PROFILE_POLICY_PATH), ProfilesPolicyConfigSchema);
    this.permissionSets = new AuditPolicyDef(path.join(directoryPath, PERMSET_POLICY_PATH), PermSetsPolicyConfigSchema);
  }
}

class AuditClassificationDef {
  public content: PermissionsConfig;

  public constructor(public filePath: string) {
    this.content = PermissionsConfigSchema.parse(yaml.load(readFileSync(filePath, 'utf-8')));
  }
}

class AuditPolicyDef<T extends PolicyConfig> {
  public content: T;

  public constructor(public filePath: string, private schema: ZodObject) {
    this.content = this.schema.parse(yaml.load(readFileSync(filePath, 'utf-8'))) as T;
  }
}
