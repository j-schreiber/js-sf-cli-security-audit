import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import yaml from 'js-yaml';
import { ZodObject } from 'zod';
import {
  CLASSIFICATION_SUBDIR,
  CUSTOM_PERMISSIONS_PATH,
  PERMSET_POLICY_PATH,
  POLICIES_SUBDIR,
  PROFILE_POLICY_PATH,
  USER_PERMISSIONS_PATH,
} from '../../config/filePaths.js';
import {
  NamedPermissionsClassification,
  PermissionsConfig,
  PermissionsConfigSchema,
  PermissionSetLikeMap,
  PermSetsPolicyConfigSchema,
  BasePolicyFileContent,
  ProfilesPolicyFileContent,
  ProfilesPolicyConfigSchema,
  RuleMap,
  PermSetsPolicyFileContent,
} from './../schema.js';

export type AuditClassification = {
  content: PermissionsConfig;
  filePath?: string;
};

export type AuditPolicy = {
  filePath?: string;
  content: BasePolicyFileContent;
  getValues(): Record<string, unknown>;
};

export type AuditPolicyDefOptions = {
  filePath?: string;
  schema?: ZodObject;
  config?: PolicyConfigBase;
};

export function isClassification(cls: unknown): cls is AuditClassification {
  return (cls as AuditClassification).content?.permissions !== undefined;
}

export function isPolicy(cls: unknown): cls is AuditPolicy {
  return (cls as AuditPolicy).content !== undefined && (cls as AuditPolicy).getValues !== undefined;
}

/**
 * Holds all parsed and validated configration file contents
 * from a source directory.
 */
export default class AuditRunConfig {
  public classifications;
  public policies;

  public constructor(directoryPath?: string) {
    this.classifications = new AuditRunClassifications(directoryPath);
    this.policies = new AuditRunPolicies(directoryPath);
  }

  /**
   * Write file content to disk and update file paths.
   */
  public write(targetDir: string): void {
    this.classifications.write(targetDir);
    this.policies.write(targetDir);
  }

  /**
   * Resolves a user permission from the underlying classification, if it exists.
   *
   * @param permissionName
   * @returns
   */
  public resolveUserPermission(permissionName: string): NamedPermissionsClassification | undefined {
    const classification = this.classifications.userPermissions?.content.permissions[permissionName];
    if (classification) {
      return {
        name: permissionName,
        ...classification,
      };
    } else {
      return undefined;
    }
  }
}

export class AuditRunClassifications {
  public userPermissions?: AuditClassificationDef;
  public customPermissions?: AuditClassificationDef;

  public constructor(directoryPath?: string) {
    if (directoryPath) {
      if (existsSync(path.join(directoryPath, USER_PERMISSIONS_PATH))) {
        this.userPermissions = new AuditClassificationDef(path.join(directoryPath, USER_PERMISSIONS_PATH));
      }
      if (existsSync(path.join(directoryPath, CUSTOM_PERMISSIONS_PATH))) {
        this.customPermissions = new AuditClassificationDef(path.join(directoryPath, CUSTOM_PERMISSIONS_PATH));
      }
    }
  }

  /**
   * Write content of classification files that exist to disk
   * and update filePath in each classification.
   *
   * @param targetDirPath
   */
  public write(targetDirPath: string): void {
    mkdirSync(path.join(targetDirPath, CLASSIFICATION_SUBDIR), { recursive: true });
    if (this.userPermissions) {
      this.userPermissions.write(path.join(targetDirPath, USER_PERMISSIONS_PATH));
    }
    if (this.customPermissions) {
      this.customPermissions.write(path.join(targetDirPath, CUSTOM_PERMISSIONS_PATH));
    }
  }
}

export class AuditRunPolicies {
  public Profiles?: AuditPolicyDef<PolicyConfigProfiles>;
  public PermissionSets?: AuditPolicyDef<PolicyConfigPermissionSets>;

  public constructor(directoryPath?: string) {
    if (directoryPath && existsSync(path.join(directoryPath, PROFILE_POLICY_PATH))) {
      this.Profiles = new AuditPolicyDef({
        filePath: path.join(directoryPath, PROFILE_POLICY_PATH),
        schema: ProfilesPolicyConfigSchema,
      });
    }
    if (directoryPath && existsSync(path.join(directoryPath, PERMSET_POLICY_PATH))) {
      this.PermissionSets = new AuditPolicyDef({
        filePath: path.join(directoryPath, PERMSET_POLICY_PATH),
        schema: PermSetsPolicyConfigSchema,
      });
    }
  }

  /**
   * Writes current file contents to the target directory
   * and updates file path references
   *
   * @param targetDirPath
   */
  public write(targetDirPath: string): void {
    mkdirSync(path.join(targetDirPath, POLICIES_SUBDIR), { recursive: true });
    this.Profiles?.write(path.join(targetDirPath, PROFILE_POLICY_PATH));
    this.PermissionSets?.write(path.join(targetDirPath, PERMSET_POLICY_PATH));
  }
}

export class AuditClassificationDef implements AuditClassification {
  public content: PermissionsConfig;

  public constructor(public filePath?: string) {
    if (filePath) {
      this.content = PermissionsConfigSchema.parse(yaml.load(readFileSync(filePath, 'utf-8')));
    } else {
      this.content = { permissions: {} };
    }
  }

  public write(targetFilePath: string): void {
    const isNew = !this.filePath;
    if (Object.entries(this.content.permissions).length > 0 && isNew) {
      writeAsYaml(this.content, targetFilePath);
      this.filePath = targetFilePath;
    }
  }
}

export class AuditPolicyDef<T extends PolicyConfigBase> implements AuditPolicy {
  public content: T;
  public filePath?: string;

  public constructor(opts: AuditPolicyDefOptions) {
    if (opts.filePath && opts.schema) {
      this.content = opts.schema.parse(yaml.load(readFileSync(opts.filePath, 'utf-8'))) as T;
      this.filePath = opts.filePath;
    } else if (opts.config) {
      this.content = opts.config as T;
    } else {
      throw Error('Cannot instantiate empty policy definition');
    }
  }

  public write(targetFilePath: string): void {
    const isNew = !this.filePath;
    if (Object.entries(this.getValues()).length > 0 || isNew) {
      writeAsYaml(this.content, targetFilePath);
      this.filePath = targetFilePath;
    }
  }

  public getValues(): Record<string, unknown> {
    return this.content.getValues();
  }
}

function writeAsYaml(fileContent: unknown, filePath: string): void {
  const yamlContent = yaml.dump(fileContent);
  writeFileSync(filePath, yamlContent);
}

abstract class PolicyConfigBase {
  public enabled: boolean;
  public rules: RuleMap;

  public constructor(conf: BasePolicyFileContent) {
    this.enabled = conf.enabled;
    this.rules = conf.rules;
  }

  public abstract getValues(): Record<string, unknown>;
}

export class PolicyConfigProfiles extends PolicyConfigBase implements ProfilesPolicyFileContent {
  public profiles: PermissionSetLikeMap;

  public constructor(conf: ProfilesPolicyFileContent) {
    super(conf);
    this.profiles = conf.profiles;
  }

  public getValues(): PermissionSetLikeMap {
    return this.profiles;
  }
}

export class PolicyConfigPermissionSets extends PolicyConfigBase implements PermSetsPolicyFileContent {
  public permissionSets!: PermissionSetLikeMap;

  public constructor(conf: PermSetsPolicyFileContent) {
    super(conf);
    this.permissionSets = conf.permissionSets;
  }

  public getValues(): PermissionSetLikeMap {
    return this.permissionSets;
  }
}
