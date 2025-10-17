import { EntityResolveError } from '../audit/types.js';
import ConnectedAppsRuleRegistry from '../config/registries/connectedApps.js';
import RuleRegistry from '../config/registries/ruleRegistry.js';
import { CONNECTED_APPS_QUERY, OAUTH_TOKEN_QUERY } from '../config/queries.js';
import MdapiRetriever from '../mdapiRetriever.js';
import { AuditContext } from './interfaces/policyRuleInterfaces.js';
import { BasePolicyFileContent } from './schema.js';
import AuditRunConfig from './interfaces/auditRunConfig.js';
import Policy, { ResolveEntityResult } from './policy.js';
import { ConnectedApp, OauthToken } from './salesforceStandardTypes.js';

export type ResolvedConnectedApp = {
  name: string;
  origin: 'Installed' | 'OauthToken' | 'Owned';
  onlyAdminApprovedUsersAllowed: boolean;
  overrideByApiSecurityAccess: boolean;
  useCount: number;
  users: string[];
};

export default class ConnectedAppPolicy extends Policy {
  public constructor(
    public config: BasePolicyFileContent,
    public auditContext: AuditRunConfig,
    registry: RuleRegistry = new ConnectedAppsRuleRegistry()
  ) {
    super(auditContext, config, registry);
  }

  // eslint-disable-next-line class-methods-use-this
  protected async resolveEntities(context: AuditContext): Promise<ResolveEntityResult> {
    const successfullyResolved: Record<string, ResolvedConnectedApp> = {};
    const ignoredEntities: Record<string, EntityResolveError> = {};
    const metadataApi = new MdapiRetriever(context.targetOrgConnection);
    let overrideByApiSecurityAccess = false;
    const apiSecurityAccessSetting = await metadataApi.retrieveConnectedAppSetting();
    if (apiSecurityAccessSetting && apiSecurityAccessSetting.enableAdminApprovedAppsOnly) {
      overrideByApiSecurityAccess = true;
    }
    const installedApps = await context.targetOrgConnection.query<ConnectedApp>(CONNECTED_APPS_QUERY);
    installedApps.records.forEach((installedApp) => {
      successfullyResolved[installedApp.Name] = {
        name: installedApp.Name,
        origin: 'Installed',
        onlyAdminApprovedUsersAllowed: installedApp.OptionsAllowAdminApprovedUsersOnly,
        overrideByApiSecurityAccess,
        useCount: 0,
        users: [],
      };
    });
    const usersOAuthToken = await context.targetOrgConnection.query<OauthToken>(OAUTH_TOKEN_QUERY);
    usersOAuthToken.records.forEach((token) => {
      if (successfullyResolved[token.AppName] === undefined) {
        successfullyResolved[token.AppName] = {
          name: token.AppName,
          origin: 'OauthToken',
          onlyAdminApprovedUsersAllowed: false,
          overrideByApiSecurityAccess,
          useCount: token.UseCount,
          users: [token.User.Username],
        };
      } else {
        successfullyResolved[token.AppName].useCount += token.UseCount;
        if (!successfullyResolved[token.AppName].users.includes(token.User.Username)) {
          successfullyResolved[token.AppName].users.push(token.User.Username);
        }
      }
    });
    // also query from tooling, to get additional information info
    return { resolvedEntities: successfullyResolved, ignoredEntities: Object.values(ignoredEntities) };
  }
}
