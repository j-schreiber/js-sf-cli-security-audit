import EventEmitter from 'node:events';
import { Connection } from '@salesforce/core';
import MDAPI from '../../mdapi/mdapi.js';
import { ConnectedApp, ResolveAppsOptions, ResolveAppsOptionsSchema, SfConnectedApp } from './connected-app.types.js';
import { CONNECTED_APPS_QUERY } from './queries.js';
import OAuthTokens from './oauth-tokens.js';

export default class ConnectedApps extends EventEmitter {
  private readonly mdapi: MDAPI;
  private readonly oauthTokenRepo: OAuthTokens;

  public constructor(private readonly con: Connection) {
    super();
    this.mdapi = MDAPI.create(this.con);
    this.oauthTokenRepo = new OAuthTokens(this.con);
    this.oauthTokenRepo.on('resolvewarning', (warning) => this.emit('resolvewarning', warning));
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
    const installedApps = await this.con.query<SfConnectedApp>(CONNECTED_APPS_QUERY);
    this.emit('entityresolve', {
      total: installedApps.totalSize,
      resolved: 0,
    });
    const apps = new Map<string, ConnectedApp>();
    for (const sfrecord of installedApps.records) {
      apps.set(sfrecord.Name, {
        name: sfrecord.Name,
        origin: 'Installed',
        onlyAdminApprovedUsersAllowed: sfrecord.OptionsAllowAdminApprovedUsersOnly,
        overrideByApiSecurityAccess: false,
        useCount: 0,
        users: [],
      });
    }
    if (definitiveOpts.withOAuthToken) {
      const usersOAuthToken = await this.oauthTokenRepo.queryAll();
      for (const sfToken of usersOAuthToken) {
        const appRef = apps.get(sfToken.AppName);
        if (appRef) {
          appRef.useCount += sfToken.UseCount;
          if (!appRef.users.includes(sfToken.User.Username)) {
            appRef.users.push(sfToken.User.Username);
          }
        } else {
          apps.set(sfToken.AppName, {
            name: sfToken.AppName,
            origin: 'OauthToken',
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
    let overrideByApiSecurityAccess = false;
    const apiSecurityAccessSetting = await this.mdapi.resolveSingleton('ConnectedAppSettings');
    if (apiSecurityAccessSetting?.enableAdminApprovedAppsOnly) {
      overrideByApiSecurityAccess = true;
    }
    for (const app of apps.values()) {
      app.overrideByApiSecurityAccess = overrideByApiSecurityAccess;
    }
    this.emit('entityresolve', {
      total: apps.size,
      resolved: apps.size,
    });
    return apps;
  }
}
