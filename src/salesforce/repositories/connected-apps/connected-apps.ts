import EventEmitter from 'node:events';
import { Connection } from '@salesforce/core';
import MDAPI from '../../mdapi/mdapi.js';
import { maxDate } from '../../utils.js';
import {
  ConnectedApp,
  OAuthUsageStats,
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
      const oauthUsage = await this.fetchOauthUsage();
      for (const [appName, appDef] of oauthUsage.entries()) {
        const appRef = appDef.appId && appIndex.get(appDef.appId) ? appIndex.get(appDef.appId) : apps.get(appName);
        if (appRef) {
          appRef.useCount += appDef.useCount;
          appRef.users = [...appDef.users.values()];
        } else {
          apps.set(appName, {
            name: appName,
            origin: 'OauthToken',
            type: 'Unknown',
            onlyAdminApprovedUsersAllowed: false,
            overrideByApiSecurityAccess: false,
            useCount: appDef.useCount,
            users: [...appDef.users.values()],
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
    const nonExternalClientApps = apps.filter((app) => app.type !== 'ExternalClientApp');
    this.emit('entityresolve', {
      total: apps.length,
      resolved: apps.length - nonExternalClientApps.length,
    });
    let overrideByApiSecurityAccess = false;
    const apiSecurityAccessSetting = await this.mdapi.resolveSingleton('ConnectedAppSettings');
    if (apiSecurityAccessSetting?.enableAdminApprovedAppsOnly) {
      overrideByApiSecurityAccess = true;
    }
    for (const app of nonExternalClientApps) {
      app.overrideByApiSecurityAccess = overrideByApiSecurityAccess;
    }
  }

  private async fetchOauthUsage(): Promise<Map<string, OAuthUsageStats>> {
    const usersOAuthToken = await this.oauthTokenRepo.queryAll();
    const stats = new Map<string, OAuthUsageStats>();
    for (const sfToken of usersOAuthToken) {
      let appStats = stats.get(sfToken.AppName);
      if (!appStats) {
        appStats = {
          appId: sfToken.AppMenuItem?.ApplicationId,
          useCount: sfToken.UseCount,
          users: new Map(),
        };
        stats.set(sfToken.AppName, appStats);
      } else {
        appStats.useCount += sfToken.UseCount;
        // appStats.lastUsed += ...
      }
      const userStats = appStats.users.get(sfToken.User.Username);
      if (userStats) {
        userStats.tokenCount++;
        userStats.useCount += sfToken.UseCount;
        userStats.lastUsed = maxDate(userStats.lastUsed, sfToken.LastUsedDate);
      } else {
        appStats.users.set(sfToken.User.Username, {
          username: sfToken.User.Username,
          useCount: sfToken.UseCount,
          lastUsed: sfToken.LastUsedDate,
          tokenCount: 1,
        });
      }
    }
    // clean optional properties that were initialised with nullish
    for (const app of stats.values()) {
      if (!app.lastUsed) {
        delete app.lastUsed;
      }
      for (const user of app.users.values()) {
        if (!user.lastUsed) {
          delete user.lastUsed;
        }
      }
    }
    return stats;
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
