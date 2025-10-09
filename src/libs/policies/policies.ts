/* eslint-disable @typescript-eslint/no-unused-vars */
import fs from 'node:fs';
import path from 'node:path';
import { Connection } from '@salesforce/core';
import { DescribeSObjectResult } from '@jsforce/jsforce-node';
import yaml from 'js-yaml';
import { AuditResult } from '../audit/types.js';
import { DEFAULT_CLASSIFICATIONS } from '../config/defaultPolicyClassification.js';
import { PermissionRiskLevelPresets, PolicyRiskLevel, PolicyWriteResult } from './types.js';
import PolicySet from './policySet.js';
import {
  PermissionsConfig,
  PermissionsClassification,
  ProfilesPolicyConfig,
  PolicyConfig,
  PermSetsPolicyConfig,
} from './schema.js';
import { CustomPermission, PermissionSet } from './salesforceStandardTypes.js';

export const CLASSIFICATION_SUBDIR = 'classification';
export const POLICIES_SUBDIR = 'policies';
export const USER_PERMISSIONS_PATH = path.join(CLASSIFICATION_SUBDIR, 'userPermissions.yml');
export const CUSTOM_PERMISSIONS_PATH = path.join(CLASSIFICATION_SUBDIR, 'customPermissions.yml');
export const PROFILE_POLICY_PATH = path.join(POLICIES_SUBDIR, 'profiles.yml');
export const PERMSET_POLICY_PATH = path.join(POLICIES_SUBDIR, 'permissionSets.yml');

export const CUSTOM_PERMS_QUERY = 'SELECT Id,MasterLabel,DeveloperName FROM CustomPermission';
export const PROFILES_QUERY =
  'SELECT Profile.Name,Profile.UserType,IsCustom FROM PermissionSet WHERE IsOwnedByProfile = TRUE';
export const PERMISSION_SETS_QUERY = 'SELECT Name,Label,IsCustom FROM PermissionSet WHERE IsOwnedByProfile = FALSE';
export default class Policies {
  /**
   * Initialises a new set of policies, based on the available permissions
   * on the target org connection.
   *
   * @param con
   */
  public static async initialize(con: Connection): Promise<PolicySet> {
    const result = new PolicySet();
    // should be modularized in self-contained initialiser / builder classes
    // per classification, policy, etc. So this class fully delegates
    // initialisation of all available policies and can easily orchestrate
    // initialisation with Promise.all()
    const permSet = await con.describe('PermissionSet');
    result.classification.userPermissions.push(...initUserPermissions(permSet));
    result.classification.customPermissions.push(...(await resolveCustomPermissions(con)));
    result.policies.profiles = await initProfilesPolicy(con);
    result.policies.permissionSets = await initPermissionSetsPolicy(con);
    result.sort();
    return result;
  }

  /**
   * Checks all policies against the target org and create an audit result
   *
   * @param con
   * @param policies
   */
  public static async audit(con: Connection, policies: PolicySet): Promise<AuditResult> {
    // from this perspective, we iterate all policies of the audit config
    // here we decide, if a policy is run (is present & enabled)
    // each policy delegates audit and iterates all enabled rules
    return Promise.resolve({ isCompliant: true, policies: {} });
  }

  /**
   * Writes all policies to disk.
   *
   * @param policies
   * @param outputDir
   */
  public static write(policies: PolicySet, outputDir: string): PolicyWriteResult {
    fs.mkdirSync(path.join(outputDir, CLASSIFICATION_SUBDIR), { recursive: true });
    fs.mkdirSync(path.join(outputDir, POLICIES_SUBDIR), { recursive: true });
    const writeConfig: Record<string, string> = {
      userPermissions: path.join(outputDir, USER_PERMISSIONS_PATH),
      customPermissions: path.join(outputDir, CUSTOM_PERMISSIONS_PATH),
      profilePolicy: path.join(outputDir, PROFILE_POLICY_PATH),
      permissionSetPolicy: path.join(outputDir, PERMSET_POLICY_PATH),
    };
    writePermClassification(policies.classification.userPermissions, writeConfig.userPermissions);
    writePermClassification(policies.classification.customPermissions, writeConfig.customPermissions);
    writePolicy(writeConfig.profilePolicy, policies.policies.profiles);
    writePolicy(writeConfig.permissionSetPolicy, policies.policies.permissionSets);
    return { paths: writeConfig };
  }
}

function writePermClassification(policies: PermissionsClassification[], outputPath: string): void {
  if (policies.length === 0) {
    return;
  }
  const fileContent: PermissionsConfig = { permissions: {} };
  policies.forEach((perm) => {
    fileContent.permissions[perm.name] = {
      label: perm.label,
      classification: perm.classification,
      reason: perm.reason,
    };
  });
  const yamlFileBody = yaml.dump(fileContent);
  fs.writeFileSync(outputPath, yamlFileBody);
}

function writePolicy(fullFilePath: string, policy?: PolicyConfig): void {
  if (policy === undefined) {
    return;
  }
  const yamlDump = yaml.dump(policy);
  fs.writeFileSync(fullFilePath, yamlDump);
}

function initUserPermissions(describe: DescribeSObjectResult): PermissionsClassification[] {
  const permFields = describe.fields.filter((field) => field.name.startsWith('Permissions'));
  return permFields.map((field) => {
    const policyName = field.name.replace('Permissions', '');
    const defaultDef = DEFAULT_CLASSIFICATIONS[policyName];
    if (defaultDef) {
      return {
        label: field.label,
        name: policyName,
        classification: defaultDef.classification,
        reason: defaultDef.reason,
      };
    } else {
      return {
        label: field.label,
        name: policyName,
        classification: PolicyRiskLevel.UNKNOWN,
      };
    }
  });
}

async function resolveCustomPermissions(con: Connection): Promise<PermissionsClassification[]> {
  const customPerms = await con.query<CustomPermission>(CUSTOM_PERMS_QUERY);
  return customPerms.records.map((cp) => ({
    name: cp.DeveloperName,
    label: cp.MasterLabel,
    classification: PolicyRiskLevel.UNKNOWN,
  }));
}

async function initProfilesPolicy(con: Connection): Promise<ProfilesPolicyConfig> {
  const profiles = await con.query<PermissionSet>(PROFILES_QUERY);
  const profilesPolicy = {
    enabled: true,
    profiles: {},
    rules: {},
  } as ProfilesPolicyConfig;
  profiles.records.forEach((profileRecord) => {
    profilesPolicy.profiles[profileRecord.Profile.Name] = { preset: PermissionRiskLevelPresets.UNKNOWN };
  });
  // TODO: Load all available profile rules
  return profilesPolicy;
}

async function initPermissionSetsPolicy(con: Connection): Promise<PermSetsPolicyConfig> {
  const permSets = await con.query<PermissionSet>(PERMISSION_SETS_QUERY);
  const permSetsPolicy = {
    enabled: true,
    permissionSets: {},
    rules: {},
  } as PermSetsPolicyConfig;
  permSets.records
    .filter((permsetRecord) => permsetRecord.IsCustom)
    .forEach((permsetRecord) => {
      permSetsPolicy.permissionSets[permsetRecord.Name] = { preset: PermissionRiskLevelPresets.UNKNOWN };
    });
  // TODO: Load all available permission set rules
  return permSetsPolicy;
}
