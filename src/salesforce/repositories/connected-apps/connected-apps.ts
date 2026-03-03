import EventEmitter from 'node:events';
import { Connection } from '@salesforce/core';
import MDAPI from '../../mdapi/mdapi.js';
import {
  ConnectedApp,
  ResolveAppsOptions,
  ResolveAppsOptionsSchema,
  SfConnectedApp,
  SfExternalAppOauthPolicy,
  SfExternalClientApp,
} from './connected-app.types.js';
import { CONNECTED_APPS_QUERY, EXTERNAL_APPS_OAUTH_POLICY, EXTERNAL_CLIENT_APPS_QUERY } from './queries.js';
import OAuthTokens from './oauth-tokens.js';

type QueryResults = {
  connectedApps: SfConnectedApp[];
  externalClientApps: SfExternalClientApp[];
  externalAppOauthPolicies: SfExternalAppOauthPolicy[];
};

export default class ConnectedApps extends EventEmitter {
  private readonly mdapi: MDAPI;
  private readonly oauthTokenRepo: OAuthTokens;

  public constructor(private readonly con: Connection) {
    super();
    this.mdapi = MDAPI.create(this.con);
    this.oauthTokenRepo = new OAuthTokens(this.con);
  }

  /**
   * Resolves all connected apps from the org. Optionally include apps
   * derived from users oauth tokens.
   *
   * @param opts
   * @returns
   */
  public async resolve(opts?: Partial<ResolveAppsOptions>): Promise<Map<string, ConnectedApp>> {
    const definitiveOpts = ResolveAppsOptionsSchema.parse(opts ?? {});
    this.emit('entityresolve', {
      total: 0,
      resolved: 0,
    });
    const installedApps = await fetchAllInstalledApps(this.con);
    const apps = initResolvedApps(installedApps);
    const appIndex = buildMapIdIndex(apps);
    this.emit('entityresolve', {
      total: apps.size,
      resolved: 0,
    });
    if (definitiveOpts.withTokenUsage) {
      const usersOAuthToken = await this.oauthTokenRepo.queryAll();
      for (const sfToken of usersOAuthToken) {
        const appRef =
          sfToken.AppMenuItem?.ApplicationId && appIndex.get(sfToken.AppMenuItem.ApplicationId)
            ? appIndex.get(sfToken.AppMenuItem.ApplicationId)
            : apps.get(sfToken.AppName);
        if (appRef) {
          appRef.useCount += sfToken.UseCount;
          if (!appRef.users.includes(sfToken.User.Username)) {
            appRef.users.push(sfToken.User.Username);
          }
        } else {
          apps.set(sfToken.AppName, {
            name: sfToken.AppName,
            origin: 'OauthToken',
            type: 'Unknown',
            onlyAdminApprovedUsersAllowed: false,
            overrideByApiSecurityAccess: false,
            useCount: sfToken.UseCount,
            users: [sfToken.User.Username],
          });
        }
      }
      this.emit('entityresolve', {
        total: apps.size,
        resolved: 0,
      });
    }
    await this.setOverrideByApiAccess(Array.from(apps.values()));
    this.emit('entityresolve', {
      total: apps.size,
      resolved: apps.size,
    });
    return apps;
  }

  private async setOverrideByApiAccess(apps: ConnectedApp[]): Promise<void> {
    this.emit('entityresolve', {
      total: apps.length,
      resolved: apps.filter((app) => app.type !== 'ConnectedApp').length,
    });
    let overrideByApiSecurityAccess = false;
    const apiSecurityAccessSetting = await this.mdapi.resolveSingleton('ConnectedAppSettings');
    if (apiSecurityAccessSetting?.enableAdminApprovedAppsOnly) {
      overrideByApiSecurityAccess = true;
    }
    for (const app of apps.filter((a) => a.type === 'ConnectedApp')) {
      app.overrideByApiSecurityAccess = overrideByApiSecurityAccess;
    }
  }
}

async function fetchAllInstalledApps(con: Connection): Promise<QueryResults> {
  const resultPromises = [
    con.query<SfConnectedApp>(CONNECTED_APPS_QUERY),
    con.query<SfExternalClientApp>(EXTERNAL_CLIENT_APPS_QUERY),
    con.query<SfExternalAppOauthPolicy>(EXTERNAL_APPS_OAUTH_POLICY),
  ];
  const results = await Promise.all(resultPromises);
  return {
    connectedApps: results[0].records as SfConnectedApp[],
    externalClientApps: results[1].records as SfExternalClientApp[],
    externalAppOauthPolicies: results[2].records as SfExternalAppOauthPolicy[],
  };
}

function initResolvedApps(result: QueryResults): Map<string, ConnectedApp> {
  const apps = new Map<string, ConnectedApp>();
  for (const sfrecord of result.connectedApps) {
    apps.set(sfrecord.Name, {
      id: sfrecord.Id,
      name: sfrecord.Name,
      origin: 'Installed',
      type: 'ConnectedApp',
      onlyAdminApprovedUsersAllowed: sfrecord.OptionsAllowAdminApprovedUsersOnly,
      overrideByApiSecurityAccess: false,
      useCount: 0,
      users: [],
    });
  }
  const policies = new Map<string, SfExternalAppOauthPolicy>();
  for (const pol of result.externalAppOauthPolicies) {
    policies.set(pol.ExternalClientApplicationId, pol);
  }
  for (const sfrecord of result.externalClientApps) {
    apps.set(sfrecord.MasterLabel, {
      id: sfrecord.Id,
      name: sfrecord.MasterLabel,
      origin: sfrecord.DistributionState === 'Local' ? 'Owned' : 'Installed',
      type: 'ExternalClientApp',
      onlyAdminApprovedUsersAllowed:
        policies.get(sfrecord.Id)?.PermittedUsersPolicyType === 'AdminApprovedPreAuthorized',
      overrideByApiSecurityAccess: false,
      useCount: 0,
      users: [],
    });
  }
  return apps;
}

function buildMapIdIndex(apps: Map<string, ConnectedApp>): Map<string, ConnectedApp> {
  const byId = new Map<string, ConnectedApp>();
  for (const app of apps.values()) {
    if (app.id) {
      byId.set(app.id, app);
    }
  }
  return byId;
}
