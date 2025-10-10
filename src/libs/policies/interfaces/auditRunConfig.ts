import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import yaml from 'js-yaml';
import z, { ZodObject } from 'zod';
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
  PermSetsPolicyConfigSchema,
  PolicyConfig,
  ProfilesPolicyConfigSchema,
} from './../schema.js';

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

class AuditRunClassifications {
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

class AuditRunPolicies {
  public profiles?: AuditPolicyDef<z.infer<typeof ProfilesPolicyConfigSchema>>;
  public permissionSets?: AuditPolicyDef<z.infer<typeof PermSetsPolicyConfigSchema>>;

  public constructor(directoryPath?: string) {
    if (directoryPath) {
      if (existsSync(path.join(directoryPath, PROFILE_POLICY_PATH))) {
        this.profiles = new AuditPolicyDef(path.join(directoryPath, PROFILE_POLICY_PATH), ProfilesPolicyConfigSchema);
      }
      if (existsSync(path.join(directoryPath, PERMSET_POLICY_PATH))) {
        this.permissionSets = new AuditPolicyDef(
          path.join(directoryPath, PERMSET_POLICY_PATH),
          PermSetsPolicyConfigSchema
        );
      }
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
    if (this.profiles) {
      const filePath = path.join(targetDirPath, PROFILE_POLICY_PATH);
      writeAsYaml(this.profiles.content, filePath);
      this.profiles.filePath = filePath;
    }
    if (this.permissionSets) {
      const filePath = path.join(targetDirPath, PERMSET_POLICY_PATH);
      writeAsYaml(this.permissionSets.content, filePath);
      this.permissionSets.filePath = filePath;
    }
  }
}

export class AuditClassificationDef {
  public content: PermissionsConfig;

  public constructor(public filePath?: string) {
    if (filePath) {
      this.content = PermissionsConfigSchema.parse(yaml.load(readFileSync(filePath, 'utf-8')));
    } else {
      this.content = { permissions: {} };
    }
  }

  public write(targetFilePath: string): void {
    // const usersPath = path.join(targetDirPath, USER_PERMISSIONS_PATH);
    const isNew = !this.filePath;
    if (Object.entries(this.content.permissions).length > 0 && isNew) {
      writeAsYaml(this.content, targetFilePath);
      this.filePath = targetFilePath;
    }
  }
}

class AuditPolicyDef<T extends PolicyConfig> {
  public content: T;

  public constructor(public filePath?: string, private schema?: ZodObject) {
    if (this.filePath && this.schema) {
      this.content = this.schema.parse(yaml.load(readFileSync(this.filePath, 'utf-8'))) as T;
    } else {
      this.content = {} as T;
    }
  }
}

function writeAsYaml(fileContent: unknown, filePath: string): void {
  const yamlContent = yaml.dump(fileContent);
  writeFileSync(filePath, yamlContent);
}
