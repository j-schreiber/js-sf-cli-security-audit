import { BasePolicyFileContent, UsersPolicyFileContent } from '../core/file-mgmt/schema.js';
import { RuleRegistries } from '../core/registries/types.js';
import { ProfilesRiskPreset } from '../core/policy-types.js';
import { PolicyNames } from '../core/policyRegistry.js';

/**
 * Initialises a new settings policy with default rules enabled.
 *
 * @returns
 */
export function initSettings(): BasePolicyFileContent {
  const content: BasePolicyFileContent = { enabled: true, rules: {} };
  ['Security', 'UserInterface', 'UserManagement', 'ConnectedApp'].forEach((settingName) => {
    content.rules[`Enforce${settingName}Settings`] = {
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
export function initUserPolicy(): UsersPolicyFileContent {
  const content: UsersPolicyFileContent = {
    ...initDefaultPolicy('users'),
    options: {
      analyseLastNDaysOfLoginHistory: 30,
      defaultRoleForMissingUsers: ProfilesRiskPreset.STANDARD_USER,
    },
  };
  return content;
}

/**
 * Initialises a default policy with all registered rules.
 *
 * @param policyName
 * @returns
 */
export function initDefaultPolicy(policyName: PolicyNames): BasePolicyFileContent {
  const content: BasePolicyFileContent = { enabled: true, rules: {} };
  RuleRegistries[policyName].registeredRules().forEach((ruleName) => {
    content.rules[ruleName] = {
      enabled: true,
    };
  });
  return content;
}
