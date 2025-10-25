import AllUsedAppsUnderManagement from '../../policies/rules/allUsedAppsUnderManagement.js';
import NoUserCanSelfAuthorize from '../../policies/rules/noUserCanSelfAuthorize.js';
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
