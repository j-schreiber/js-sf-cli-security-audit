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
import { PermissionsConfig, PermissionsPolicy } from './schema.js';
import { CustomPermission } from './salesforceStandardTypes.js';

export const PERMISSIONS_SUBDIR = 'permissions';
export const USER_PERMISSIONS_PATH = path.join(PERMISSIONS_SUBDIR, 'userPermissions.yml');
export const CUSTOM_PERMISSIONS_PATH = path.join(PERMISSIONS_SUBDIR, 'customPermissions.yml');

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
    result.userPermissions.push(...initUserPermissions(permSet));
    result.customPermissions.push(...(await resolveCustomPermissions(con)));
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
    fs.mkdirSync(path.join(outputDir, PERMISSIONS_SUBDIR), { recursive: true });
    const writeConfig: Record<string, string> = {
      userPermissions: path.join(outputDir, USER_PERMISSIONS_PATH),
      customPermissions: path.join(outputDir, CUSTOM_PERMISSIONS_PATH),
    };
    writePermissionsPolicies(policies.userPermissions, writeConfig.userPermissions);
    writePermissionsPolicies(policies.customPermissions, writeConfig.customPermissions);
    return { paths: writeConfig };
  }
}

function writePermissionsPolicies(policies: PermissionsPolicy[], outputPath: string): void {
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

function initUserPermissions(describe: DescribeSObjectResult): PermissionsPolicy[] {
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

async function resolveCustomPermissions(con: Connection): Promise<PermissionsPolicy[]> {
  const customPerms = await con.query<CustomPermission>('SELECT Id,MasterLabel,DeveloperName FROM CustomPermission');
  return customPerms.records.map((cp) => ({
    name: cp.DeveloperName,
    label: cp.MasterLabel,
    classification: PolicyRiskLevel.UNKNOWN,
  }));
}
