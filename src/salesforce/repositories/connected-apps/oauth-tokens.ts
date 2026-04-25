import { EventEmitter } from 'node:events';
import { Messages } from '@salesforce/core';
import { ResolveLifecycle } from '../../resolve-entity-lifecycle-bus.js';
import { envVars } from '../../../ux/environment.js';
import { chunkArray } from '../../utils.js';
import SfConnection from '../../connection.js';
import { SfMinimalUser, SfOauthToken } from './connected-app.types.js';
import {
  ALL_EXISTING_USER_IDS,
  COUNT_TOKEN_QUERY,
  formatCountSoql,
  formatTokenSoql,
  OAUTH_TOKEN_QUERY,
} from './queries.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'metadataretrieve');

type QueryOptions = {
  /** Result size for query when batching starts */
  totalSizeThreshold: number;
  /** Number of user ids that are batched in a retrieve */
  startingBatchSize: number;
};

export default class OAuthTokens extends EventEmitter {
  private readonly defaultOptions: QueryOptions = {
    totalSizeThreshold: envVars.resolve('SAE_MAX_OAUTH_TOKEN_THRESHOLD') ?? 2500,
    startingBatchSize: envVars.resolve('SAE_OAUTH_TOKEN_BATCH_SIZE') ?? 256,
  };
  private readonly maxUserCount;

  public constructor(private readonly con: SfConnection) {
    super();
    this.maxUserCount = envVars.resolve('SAE_MAX_USERS_LIMIT') ?? 100_000;
  }

  public async queryAll(options?: QueryOptions): Promise<SfOauthToken[]> {
    const definitiveOptions = { ...this.defaultOptions, ...options };
    const countResult = await this.con.query(COUNT_TOKEN_QUERY);
    let allTokens: SfOauthToken[];
    if (countResult.totalSize > definitiveOptions.totalSizeThreshold) {
      const userIds = await this.fetchUserIds();
      allTokens = await this.batchQueryTokens(userIds, definitiveOptions);
    } else {
      const tokenResult = await this.con.query<SfOauthToken>(OAUTH_TOKEN_QUERY);
      allTokens = tokenResult.records;
      if (!tokenResult.done) {
        ResolveLifecycle.emitWarn(
          messages.getMessage('warning.NotAllOauthTokenReturned', [tokenResult.totalSize, tokenResult.records.length])
        );
      }
    }
    if (countResult.totalSize > allTokens.length) {
      ResolveLifecycle.emitWarn(
        messages.getMessage('warning.NotAllOauthTokenReturned', [countResult.totalSize, allTokens.length])
      );
    }
    return allTokens;
  }

  private async batchQueryTokens(allUserIds: string[], options: QueryOptions): Promise<SfOauthToken[]> {
    const userIdChunks = chunkArray(allUserIds, options.startingBatchSize);
    const queryPromises = userIdChunks.map((idChunk) => this.fetchTokenChunk(idChunk, options));
    const results = await Promise.all(queryPromises);
    return results.flat();
  }

  private async fetchTokenChunk(userIds: string[], options: QueryOptions): Promise<SfOauthToken[]> {
    const countResult = await this.con.query(formatCountSoql(userIds));
    if (countResult.totalSize > options.totalSizeThreshold && options.startingBatchSize > 1) {
      const reducedChunkSize = Math.floor(options.startingBatchSize / 2);
      const subChunks = chunkArray(userIds, reducedChunkSize);
      const subResultProms = subChunks.map((chunk) =>
        this.fetchTokenChunk(chunk, {
          totalSizeThreshold: options.totalSizeThreshold,
          startingBatchSize: reducedChunkSize,
        })
      );
      const subResults = await Promise.all(subResultProms);
      return subResults.flat();
    } else {
      const direktResult = await this.con.query<SfOauthToken>(formatTokenSoql(userIds));
      return direktResult.records;
    }
  }

  private async fetchUserIds(): Promise<string[]> {
    const userResult = await this.con.query<SfMinimalUser>(ALL_EXISTING_USER_IDS, false, {
      autoFetch: true,
      maxFetch: this.maxUserCount,
    });
    if (userResult.totalSize > this.maxUserCount) {
      ResolveLifecycle.emitWarn(
        messages.getMessage('warning.TooManyUsersIncreaseLimit', [userResult.totalSize, this.maxUserCount])
      );
    }
    return userResult.records.map((userRecord) => userRecord.Id);
  }
}
