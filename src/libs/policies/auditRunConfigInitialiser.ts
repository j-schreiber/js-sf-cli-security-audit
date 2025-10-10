import { Connection } from '@salesforce/core';
import { DescribeSObjectResult } from '@jsforce/jsforce-node';
import { DEFAULT_CLASSIFICATIONS } from '../config/defaultPolicyClassification.js';
import { CUSTOM_PERMS_QUERY, PERMISSION_SETS_QUERY, PROFILES_QUERY } from '../config/queries.js';
import AuditRunConfig, { AuditClassificationDef } from './interfaces/auditRunConfig.js';
import {
  NamedPermissionsClassification,
  PermissionsClassification,
  PermSetsPolicyConfig,
  ProfilesPolicyConfig,
} from './schema.js';
import { PermissionRiskLevelPresets, PolicyRiskLevel, resolveRiskLevelOrdinalValue } from './types.js';
import { CustomPermission, PermissionSet } from './salesforceStandardTypes.js';

export default class AuditRunConfigInitialiser {
  public static async initConfigFromOrg(con: Connection): Promise<AuditRunConfig> {
    const conf = new AuditRunConfig();
    // TODO: Shouldn't be too hard to delegate initialisation to single modules
    conf.classifications.userPermissions = await initUserPermissions(con);
    conf.classifications.customPermissions = await resolveCustomPermissions(con);
    conf.policies.profiles = await ProfilesPolicyInitialiser.init(con);
    conf.policies.permissionSets = await PermissionSetsPolicyInitialiser.init(con);
    return conf;
  }
}

async function initUserPermissions(con: Connection): Promise<AuditClassificationDef> {
  const permSet = await con.describe('PermissionSet');
  const strippedPerms: Record<string, PermissionsClassification> = {};
  const perms = parsePermissionsFromPermSet(permSet);
  perms.sort(classificationSorter);
  perms.forEach(
    (perm) =>
      (strippedPerms[perm.name] = {
        label: perm.label,
        classification: perm.classification,
        reason: perm.reason,
      })
  );
  const result = new AuditClassificationDef();
  result.content.permissions = strippedPerms;
  return result;
}

async function resolveCustomPermissions(con: Connection): Promise<AuditClassificationDef> {
  const customPerms = await con.query<CustomPermission>(CUSTOM_PERMS_QUERY);
  const perms = customPerms.records.map((cp) => ({
    name: cp.DeveloperName,
    label: cp.MasterLabel,
    classification: PolicyRiskLevel.UNKNOWN,
  }));
  perms.sort(classificationSorter);
  const permsMap: Record<string, PermissionsClassification> = {};
  perms.forEach(
    (perm) =>
      (permsMap[perm.name] = {
        label: perm.label,
        classification: perm.classification,
      })
  );
  const result = new AuditClassificationDef();
  result.content.permissions = permsMap;
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

class ProfilesPolicyInitialiser {
  public static async init(con: Connection): Promise<{ content: ProfilesPolicyConfig }> {
    const profiles = await con.query<PermissionSet>(PROFILES_QUERY);
    const profilesPolicy = {
      enabled: true,
      profiles: {},
      rules: {},
    } as ProfilesPolicyConfig;
    profiles.records.forEach((profileRecord) => {
      profilesPolicy.profiles[profileRecord.Profile.Name] = { preset: PermissionRiskLevelPresets.UNKNOWN };
    });
    profilesPolicy.rules['EnforceClassificationPresets'] = {
      enabled: true,
    };
    return { content: profilesPolicy };
  }
}

class PermissionSetsPolicyInitialiser {
  public static async init(con: Connection): Promise<{ content: PermSetsPolicyConfig }> {
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
    permSetsPolicy.rules['EnforceClassificationPresets'] = {
      enabled: true,
    };
    return { content: permSetsPolicy };
  }
}

const classificationSorter = (a: NamedPermissionsClassification, b: NamedPermissionsClassification): number =>
  resolveRiskLevelOrdinalValue(a.classification) - resolveRiskLevelOrdinalValue(b.classification);
