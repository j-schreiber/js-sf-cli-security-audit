import AllUsedAppsUnderManagement from './rules/allUsedAppsUnderManagement.js';
import NoUserCanSelfAuthorize from './rules/noUserCanSelfAuthorize.js';
import RuleRegistry from './ruleRegistry.js';

export type ResolvedConnectedApp = {
  name: string;
  origin: 'Installed' | 'OauthToken' | 'Owned';
  onlyAdminApprovedUsersAllowed: boolean;
  overrideByApiSecurityAccess: boolean;
  useCount: number;
  users: string[];
};
export default class ConnectedAppsRuleRegistry extends RuleRegistry {
  public constructor() {
    super({
      AllUsedAppsUnderManagement,
      NoUserCanSelfAuthorize,
    });
  }
}

export const ConnectedAppsRegistry = new ConnectedAppsRuleRegistry();
