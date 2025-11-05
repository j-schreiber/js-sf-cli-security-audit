import { Connection } from '@salesforce/core';
import { ACTIVE_USERS_QUERY, PERMISSION_SETS_QUERY, PROFILES_QUERY } from '../core/constants.js';
import { PermissionSet, User } from '../policies/salesforceStandardTypes.js';
import {
  BasePolicyFileContent,
  PermSetsPolicyFileContent,
  ProfilesPolicyFileContent,
  UsersPolicyConfig,
  UsersPolicyFileContent,
} from '../core/file-mgmt/schema.js';
import { RuleRegistries } from '../core/registries/types.js';
import { ProfilesRiskPreset } from '../core/policy-types.js';

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
  const content: ProfilesPolicyFileContent = { enabled: true, rules: {}, profiles: {} };
  profiles.records.forEach((permsetRecord) => {
    content.profiles[permsetRecord.Profile.Name] = { preset: ProfilesRiskPreset.UNKNOWN };
  });
  RuleRegistries.Profiles.registeredRules().forEach((ruleName) => {
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
    rules: {},
    permissionSets: {},
  };
  permSets.records
    .filter((permsetRecord) => permsetRecord.IsCustom)
    .forEach((permsetRecord) => {
      content.permissionSets[permsetRecord.Name] = { preset: ProfilesRiskPreset.UNKNOWN };
    });
  RuleRegistries.PermissionSets.registeredRules().forEach((ruleName) => {
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
  RuleRegistries.ConnectedApps.registeredRules().forEach((ruleName) => {
    content.rules[ruleName] = {
      enabled: true,
    };
  });
  return content;
}

/**
 * Initialises a users policy with all users flagged as standard user
 *
 * @param targetOrgCon
 */
export async function initUsers(targetOrgCon: Connection): Promise<UsersPolicyFileContent> {
  const users = await targetOrgCon.query<User>(ACTIVE_USERS_QUERY);
  const content: UsersPolicyFileContent = {
    enabled: true,
    options: UsersPolicyConfig.parse({}),
    rules: {},
    users: {},
  };
  users.records.forEach((userRecord) => {
    content.users[userRecord.Username] = { role: ProfilesRiskPreset.STANDARD_USER };
  });
  RuleRegistries.Users.registeredRules().forEach((ruleName) => {
    content.rules[ruleName] = {
      enabled: true,
    };
  });
  return content;
}
