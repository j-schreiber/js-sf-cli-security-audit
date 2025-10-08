/* eslint-disable @typescript-eslint/no-unused-vars */
import fs from 'node:fs';
import path from 'node:path';
import { Connection } from '@salesforce/core';
import { DescribeSObjectResult } from '@jsforce/jsforce-node';
import yaml from 'js-yaml';
import { AuditResult } from '../audit/types.js';
import { DEFAULT_CLASSIFICATIONS } from '../config/defaultPolicyClassification.js';
import { PolicyRiskLevel, PolicyWriteResult } from './types.js';
import PolicySet from './policySet.js';
import { PermissionsConfig, PermissionsClassification, ProfilesPolicyConfig, PolicyConfig } from './schema.js';
import { CustomPermission, PermissionSet } from './salesforceStandardTypes.js';

export const CLASSIFICATION_SUBDIR = 'classification';
export const POLICIES_SUBDIR = 'policies';
export const USER_PERMISSIONS_PATH = path.join(CLASSIFICATION_SUBDIR, 'userPermissions.yml');
export const CUSTOM_PERMISSIONS_PATH = path.join(CLASSIFICATION_SUBDIR, 'customPermissions.yml');
export const PROFILE_POLICY_PATH = path.join(POLICIES_SUBDIR, 'profiles.yml');

export const CUSTOM_PERMS_QUERY = 'SELECT Id,MasterLabel,DeveloperName FROM CustomPermission';
export const PROFILES_QUERY =
  'SELECT Profile.Name,Profile.UserType,IsCustom FROM PermissionSet WHERE IsOwnedByProfile = TRUE';

export default class Policies {
  /**
   * Initialises a new set of policies, based on the available permissions
   * on the target org connection.
   *
   * @param con
   */
  public static async initialize(con: Connection): Promise<PolicySet> {
    const result = new PolicySet();
    const permSet = await con.describe('PermissionSet');
    result.classification.userPermissions.push(...initUserPermissions(permSet));
    result.classification.customPermissions.push(...(await resolveCustomPermissions(con)));
    result.policies.profiles = await initProfilesPolicy(con);
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
    // do stuff
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
    };
    writePermClassification(policies.classification.userPermissions, writeConfig.userPermissions);
    writePermClassification(policies.classification.customPermissions, writeConfig.customPermissions);
    writePolicy(writeConfig.profilePolicy, policies.policies.profiles);
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
  const profiles = await con.query<PermissionSet>(
    'SELECT Profile.Name,Profile.UserType,IsCustom FROM PermissionSet WHERE IsOwnedByProfile = TRUE'
  );
  const profilesPolicy = {
    enabled: true,
    profiles: {},
    rules: {},
  } as ProfilesPolicyConfig;
  profiles.records.forEach((profileRecord) => {
    profilesPolicy.profiles[profileRecord.Profile.Name] = { preset: 'Unknown', enforceIpRanges: false };
  });
  // TODO: Load all available profile rules
  return profilesPolicy;
}
