import { PolicyConfig, UserPrivilegeLevel } from '../audit-engine/index.js';

export const DefaultPolicyDefinitions: Record<string, () => Partial<PolicyConfig>> = {
  users: () => ({
    options: {
      analyseLastNDaysOfLoginHistory: 30,
      defaultRoleForMissingUsers: UserPrivilegeLevel.STANDARD_USER,
    },
  }),
  settings: () => ({
    enabled: true,
    rules: {
      EnforceApexSettings: { enabled: true },
      EnforceSecuritySettings: { enabled: true },
      EnforceUserInterfaceSettings: { enabled: true },
      EnforceUserManagementSettings: { enabled: true },
      EnforceConnectedAppSettings: { enabled: true },
    },
  }),
};
