import { Connection } from '@salesforce/core';
import { DescribeSObjectResult } from '@jsforce/jsforce-node';
import { NamedPermissionsClassification, PermissionsConfig } from '../../core/file-mgmt/schema.js';
import { DEFAULT_CLASSIFICATIONS } from '../../config/defaultPolicyClassification.js';
import { PolicyRiskLevel, resolveRiskLevelOrdinalValue } from '../types.js';
import { CUSTOM_PERMS_QUERY } from '../../config/queries.js';
import { CustomPermission } from '../salesforceStandardTypes.js';

/**
 * Initialises a fresh set of user permissions from target org connection
 *
 * @param con
 * @returns
 */
export async function initUserPermissions(con: Connection): Promise<PermissionsConfig> {
  const permSet = await con.describe('PermissionSet');
  const result: PermissionsConfig = { permissions: {} };
  const perms = parsePermissionsFromPermSet(permSet);
  perms.sort(classificationSorter);
  perms.forEach(
    (perm) =>
      (result.permissions[perm.name] = {
        label: sanitiseLabel(perm.label),
        classification: perm.classification,
        reason: perm.reason,
      })
  );
  return result;
}

/**
 * Initialises a fresh set of custom permissions from the target org
 *
 * @param con
 * @returns
 */
export async function initCustomPermissions(con: Connection): Promise<PermissionsConfig | undefined> {
  const result: PermissionsConfig = { permissions: {} };
  const customPerms = await con.query<CustomPermission>(CUSTOM_PERMS_QUERY);
  if (customPerms.records.length === 0) {
    return undefined;
  }
  const perms = customPerms.records.map((cp) => ({
    name: cp.DeveloperName,
    label: cp.MasterLabel,
    classification: PolicyRiskLevel.UNKNOWN,
  }));
  perms.forEach(
    (perm) =>
      (result.permissions[perm.name] = {
        label: perm.label,
        classification: perm.classification,
      })
  );
  return result;
}

function parsePermissionsFromPermSet(describe: DescribeSObjectResult): NamedPermissionsClassification[] {
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

function sanitiseLabel(rawLabel?: string): string | undefined {
  return rawLabel?.replace(/[ \t]+$|[\r\n]+/g, '');
}

export const classificationSorter = (a: NamedPermissionsClassification, b: NamedPermissionsClassification): number =>
  resolveRiskLevelOrdinalValue(a.classification) - resolveRiskLevelOrdinalValue(b.classification);
