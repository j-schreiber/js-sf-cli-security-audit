import { EventEmitter } from 'node:events';
import { Connection } from '@salesforce/core';
import { ResolveLifecycle } from '../../resolve-entity-lifecycle-bus.js';
import { SfOauthToken } from './connected-app.types.js';

// const OAUTH_OBJECT_MAX_LIMIT = 2500;
export const OAUTH_TOKEN_QUERY = 'SELECT User.Username,UseCount,AppName FROM OauthToken';

export default class OAuthTokens extends EventEmitter {
  public constructor(private readonly con: Connection) {
    super();
  }

  public async queryAll(): Promise<SfOauthToken[]> {
    const tokenResult = await this.con.query<SfOauthToken>(OAUTH_TOKEN_QUERY, {
      autoFetch: true,
    });
    if (!tokenResult.done) {
      ResolveLifecycle.emitWarn(
        `The org has ${tokenResult.totalSize} oauth tokens, but only ${tokenResult.records.length} were retrieved. Results may be incomplete.`
      );
    }
    return tokenResult.records;
  }
}
