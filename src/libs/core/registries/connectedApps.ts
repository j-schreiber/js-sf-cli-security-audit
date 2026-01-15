import AllUsedAppsUnderManagement from './rules/allUsedAppsUnderManagement.js';
import NoUserCanSelfAuthorize from './rules/noUserCanSelfAuthorize.js';
import RuleRegistry from './ruleRegistry.js';

export default class ConnectedAppsRuleRegistry extends RuleRegistry {
  public constructor() {
    super({
      AllUsedAppsUnderManagement,
      NoUserCanSelfAuthorize,
    });
  }
}

export const ConnectedAppsRegistry = new ConnectedAppsRuleRegistry();
