import { Connection } from '@salesforce/core';
import { PERMISSION_SETS_QUERY, PROFILES_QUERY } from '../../config/queries.js';
import { PermissionSet } from '../salesforceStandardTypes.js';
import {
  BasePolicyFileContent,
  PermSetsPolicyFileContent,
  ProfilesPolicyFileContent,
} from '../../config/audit-run/schema.js';
import { ProfilesRegistry } from '../../config/registries/profiles.js';
import { PermissionRiskLevelPresets } from '../types.js';
import { PermissionSetsRegistry } from '../../config/registries/permissionSets.js';
import { ConnectedAppsRegistry } from '../../config/registries/connectedApps.js';

/**
 * Initialises a new profiles policy with the local org's
 * profiles and all default rules enabled.
 *
 * @param targetOrgCon
 * @param targetDir
 * @returns
 */
export async function initProfiles(targetOrgCon: Connection): Promise<ProfilesPolicyFileContent> {
  const profiles = await targetOrgCon.query<PermissionSet>(PROFILES_QUERY);
  const content: ProfilesPolicyFileContent = { enabled: true, profiles: {}, rules: {} };
  profiles.records.forEach((permsetRecord) => {
    content.profiles[permsetRecord.Profile.Name] = { preset: PermissionRiskLevelPresets.UNKNOWN };
  });
  ProfilesRegistry.registeredRules().forEach((ruleName) => {
    content.rules[ruleName] = {
      enabled: true,
    };
  });
  return content;
}

/**
 * Initialises a new permission sets policy with the local org's custom
 * permissions and all default rules enabled.
 *
 * @param targetOrgCon
 * @returns
 */
export async function initPermissionSets(targetOrgCon: Connection): Promise<PermSetsPolicyFileContent> {
  const permSets = await targetOrgCon.query<PermissionSet>(PERMISSION_SETS_QUERY);
  const content: PermSetsPolicyFileContent = {
    enabled: true,
    permissionSets: {},
    rules: {},
  };
  permSets.records
    .filter((permsetRecord) => permsetRecord.IsCustom)
    .forEach((permsetRecord) => {
      content.permissionSets[permsetRecord.Name] = { preset: PermissionRiskLevelPresets.UNKNOWN };
    });
  PermissionSetsRegistry.registeredRules().forEach((ruleName) => {
    content.rules[ruleName] = {
      enabled: true,
    };
  });
  return content;
}

/**
 * Initialises a new connected apps policy with default rules enabled.
 *
 * @returns
 */
export function initConnectedApps(): BasePolicyFileContent {
  const content: BasePolicyFileContent = { enabled: true, rules: {} };
  ConnectedAppsRegistry.registeredRules().forEach((ruleName) => {
    content.rules[ruleName] = {
      enabled: true,
    };
  });
  return content;
}
