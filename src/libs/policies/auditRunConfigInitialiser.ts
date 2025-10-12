import { Connection } from '@salesforce/core';
import { DescribeSObjectResult } from '@jsforce/jsforce-node';
import { DEFAULT_CLASSIFICATIONS } from '../config/defaultPolicyClassification.js';
import { CUSTOM_PERMS_QUERY, PERMISSION_SETS_QUERY, PROFILES_QUERY } from '../config/queries.js';
import AuditRunConfig, {
  AuditClassificationDef,
  AuditPolicyDef,
  PolicyConfigPermissionSets,
  PolicyConfigProfiles,
} from './interfaces/auditRunConfig.js';
import {
  NamedPermissionsClassification,
  PermissionsClassification,
  PermSetsPolicyFileContent,
  ProfilesPolicyFileContent,
} from './schema.js';
import { PermissionRiskLevelPresets, PolicyRiskLevel, resolveRiskLevelOrdinalValue } from './types.js';
import { CustomPermission, PermissionSet } from './salesforceStandardTypes.js';

export default class AuditRunConfigInitialiser {
  public static async initConfigFromOrg(con: Connection): Promise<AuditRunConfig> {
    const conf = new AuditRunConfig();
    // TODO: Shouldn't be too hard to delegate initialisation to single modules
    conf.classifications.userPermissions = await initUserPermissions(con);
    conf.classifications.customPermissions = await resolveCustomPermissions(con);
    conf.policies.Profiles = await ProfilesPolicyInitialiser.init(con);
    conf.policies.PermissionSets = await PermissionSetsPolicyInitialiser.init(con);
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
  public static async init(con: Connection): Promise<AuditPolicyDef<PolicyConfigProfiles>> {
    const profiles = await con.query<PermissionSet>(PROFILES_QUERY);
    const policyContent = {
      enabled: true,
      profiles: {},
      rules: {},
    } as ProfilesPolicyFileContent;
    profiles.records.forEach((permsetRecord) => {
      policyContent.profiles[permsetRecord.Profile.Name] = { preset: PermissionRiskLevelPresets.UNKNOWN };
    });
    policyContent.rules['EnforceClassificationPresets'] = {
      enabled: true,
    };
    return new AuditPolicyDef({ config: new PolicyConfigProfiles(policyContent) });
  }
}

class PermissionSetsPolicyInitialiser {
  public static async init(con: Connection): Promise<AuditPolicyDef<PolicyConfigPermissionSets>> {
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
    permSetsPolicy.rules['EnforceClassificationPresets'] = {
      enabled: true,
    };
    return new AuditPolicyDef({ config: new PolicyConfigPermissionSets(permSetsPolicy) });
  }
}

const classificationSorter = (a: NamedPermissionsClassification, b: NamedPermissionsClassification): number =>
  resolveRiskLevelOrdinalValue(a.classification) - resolveRiskLevelOrdinalValue(b.classification);
