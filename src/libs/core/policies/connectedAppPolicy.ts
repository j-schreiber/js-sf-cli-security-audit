import { EntityResolveError } from '../result-types.js';
import { AuditRunConfig, BasePolicyFileContent } from '../file-mgmt/schema.js';
import { CONNECTED_APPS_QUERY, OAUTH_TOKEN_QUERY } from '../constants.js';
import { AuditContext } from '../registries/types.js';
import { ConnectedAppsRegistry, ResolvedConnectedApp } from '../registries/connectedApps.js';
import MDAPI from '../mdapi/mdapiRetriever.js';
import Policy, { getTotal, ResolveEntityResult } from './policy.js';
import { ConnectedApp, OauthToken } from './salesforceStandardTypes.js';

export default class ConnectedAppPolicy extends Policy<ResolvedConnectedApp> {
  public constructor(
    public config: BasePolicyFileContent,
    public auditConfig: AuditRunConfig,
    registry = ConnectedAppsRegistry
  ) {
    super(config, auditConfig, registry);
  }

  // eslint-disable-next-line class-methods-use-this
  protected async resolveEntities(context: AuditContext): Promise<ResolveEntityResult<ResolvedConnectedApp>> {
    const successfullyResolved: Record<string, ResolvedConnectedApp> = {};
    const ignoredEntities: Record<string, EntityResolveError> = {};
    const metadataApi = new MDAPI(context.targetOrgConnection);
    this.emit('entityresolve', {
      total: 0,
      resolved: 0,
    });
    const installedApps = await context.targetOrgConnection.query<ConnectedApp>(CONNECTED_APPS_QUERY);
    this.emit('entityresolve', {
      total: installedApps.totalSize,
      resolved: 0,
    });
    installedApps.records.forEach((installedApp) => {
      successfullyResolved[installedApp.Name] = {
        name: installedApp.Name,
        origin: 'Installed',
        onlyAdminApprovedUsersAllowed: installedApp.OptionsAllowAdminApprovedUsersOnly,
        overrideByApiSecurityAccess: false,
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
          overrideByApiSecurityAccess: false,
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
    this.emit('entityresolve', {
      total: Object.keys(successfullyResolved).length,
      resolved: 0,
    });
    let overrideByApiSecurityAccess = false;
    const apiSecurityAccessSetting = await metadataApi.resolveSingleton('ConnectedAppSettings');
    if (apiSecurityAccessSetting && apiSecurityAccessSetting.enableAdminApprovedAppsOnly) {
      overrideByApiSecurityAccess = true;
    }
    Object.values(successfullyResolved).forEach((conApp) => {
      // eslint-disable-next-line no-param-reassign
      conApp.overrideByApiSecurityAccess = overrideByApiSecurityAccess;
    });
    const result = { resolvedEntities: successfullyResolved, ignoredEntities: Object.values(ignoredEntities) };
    this.emit('entityresolve', {
      total: getTotal(result),
      resolved: getTotal(result),
    });
    // also query from tooling, to get additional information info
    return result;
  }
}
