import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import yaml from 'js-yaml';
import { Connection } from '@salesforce/core';
import { ZodObject } from 'zod';
import {
  CLASSIFICATION_SUBDIR,
  CONNECTED_APPS_POLICY_PATH,
  CUSTOM_PERMISSIONS_PATH,
  PERMSET_POLICY_PATH,
  POLICIES_SUBDIR,
  PROFILE_POLICY_PATH,
  USER_PERMISSIONS_PATH,
} from '../../config/filePaths.js';
import { PermissionRiskLevelPresets } from '../types.js';
import { PERMISSION_SETS_QUERY } from '../../config/queries.js';
import { PermissionSet } from '../salesforceStandardTypes.js';
import PermSetsRuleRegistry from '../../config/registries/permissionSets.js';
import ConnectedAppsRuleRegistry from '../../config/registries/connectedApps.js';
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
  PermissionsClassification,
  PolicyConfigSchema,
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
    const sanitisedPath = directoryPath && directoryPath.length > 0 ? directoryPath : '.';
    this.classifications = new AuditRunClassifications(sanitisedPath);
    this.policies = new AuditRunPolicies(sanitisedPath);
  }

  /**
   * Initialise a new audit run config from target org
   *
   * @param con
   */
  public static async init(con: Connection): Promise<AuditRunConfig> {
    const conf = new AuditRunConfig();
    await conf.policies.init(con);
    return conf;
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
    return this.classifications.userPermissions?.resolve(permissionName);
  }

  /**
   * Resolves a custom permission from the underlying classification, if it exists.
   *
   * @param permissionName
   * @returns
   */
  public resolveCustomPermission(permissionName: string): NamedPermissionsClassification | undefined {
    return this.classifications.customPermissions?.resolve(permissionName);
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
  public ConnectedApps?: AuditPolicyDef<PolicyConfigConnectedApps>;

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
    if (directoryPath && existsSync(path.join(directoryPath, CONNECTED_APPS_POLICY_PATH))) {
      this.ConnectedApps = new AuditPolicyDef({
        filePath: path.join(directoryPath, CONNECTED_APPS_POLICY_PATH),
        schema: PolicyConfigSchema,
      });
    }
  }

  /**
   * Initialises empty policies from a target org connection
   *
   * @param con
   */
  public async init(con: Connection): Promise<void> {
    this.ConnectedApps = new AuditPolicyDef({ config: PolicyConfigConnectedApps.init() });
    this.PermissionSets = new AuditPolicyDef({ config: await PolicyConfigPermissionSets.init(con) });
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
    this.ConnectedApps?.write(path.join(targetDirPath, CONNECTED_APPS_POLICY_PATH));
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

  /**
   * Adds a permission config to the internal content map and sanitises
   * strings from invalid characters.
   *
   * @param permName
   * @param permConfig
   */
  public set(permName: string, permConfig: PermissionsClassification): void {
    this.content.permissions[permName] = { ...permConfig, label: permConfig.label?.replace(/[ \t]+$|[\r\n]+/g, '') };
  }

  /**
   * Resolves a permission name to a "named config" that contains the name
   * or undefined, if the permission does not exist.
   *
   * @param permName
   */
  public resolve(permName: string): NamedPermissionsClassification | undefined {
    if (this.content.permissions[permName]) {
      return {
        name: permName,
        ...this.content.permissions[permName],
      };
    } else {
      return undefined;
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
  const yamlContent = yaml.dump(fileContent, { lineWidth: 140 });
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
  public permissionSets: PermissionSetLikeMap;

  public constructor(conf: PermSetsPolicyFileContent) {
    super(conf);
    this.permissionSets = conf.permissionSets;
  }

  public static async init(con: Connection): Promise<PolicyConfigPermissionSets> {
    const permSets = await con.query<PermissionSet>(PERMISSION_SETS_QUERY);
    const permSetsPolicy = {
      enabled: true,
      permissionSets: {},
      rules: {},
    } as PermSetsPolicyFileContent;
    permSets.records
      .filter((permsetRecord) => permsetRecord.IsCustom)
      .forEach((permsetRecord) => {
        permSetsPolicy.permissionSets[permsetRecord.Name] = { preset: PermissionRiskLevelPresets.UNKNOWN };
      });
    const defaultReg = new PermSetsRuleRegistry();
    defaultReg.registeredRules().forEach((ruleName) => {
      permSetsPolicy.rules[ruleName] = {
        enabled: true,
      };
    });
    return new PolicyConfigPermissionSets(permSetsPolicy);
  }

  public getValues(): PermissionSetLikeMap {
    return this.permissionSets;
  }
}
export class PolicyConfigConnectedApps extends PolicyConfigBase implements BasePolicyFileContent {
  public constructor(conf: BasePolicyFileContent) {
    super(conf);
  }

  public static init(): PolicyConfigConnectedApps {
    const enabledRules: RuleMap = {};
    const defaultReg = new ConnectedAppsRuleRegistry();
    defaultReg.registeredRules().forEach((ruleName) => {
      enabledRules[ruleName] = {
        enabled: true,
      };
    });
    return new PolicyConfigConnectedApps({ enabled: true, rules: enabledRules });
  }

  // eslint-disable-next-line class-methods-use-this
  public getValues(): Record<string, unknown> {
    return {};
  }
}
