import { EventEmitter } from 'node:events';
import { Connection, Messages } from '@salesforce/core';
import { ResolveLifecycle } from '../../resolve-entity-lifecycle-bus.js';
import { envVars } from '../../../ux/environment.js';
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

  public constructor(private readonly con: Connection) {
    super();
  }

  public async queryAll(options?: QueryOptions): Promise<SfOauthToken[]> {
    const definitiveOptions = { ...this.defaultOptions, ...options };
    const countResult = await this.con.query(COUNT_TOKEN_QUERY);
    if (countResult.totalSize > definitiveOptions.totalSizeThreshold) {
      const batchResult = await this.batchQueryTokens(definitiveOptions);
      return batchResult;
    } else {
      const tokenResult = await this.con.query<SfOauthToken>(OAUTH_TOKEN_QUERY, {
        autoFetch: true,
      });
      if (!tokenResult.done) {
        ResolveLifecycle.emitWarn(
          messages.getMessage('warning.NotAllOauthTokenReturned', [tokenResult.totalSize, tokenResult.records.length])
        );
      } else if (countResult.totalSize > tokenResult.totalSize) {
        ResolveLifecycle.emitWarn(
          messages.getMessage('warning.NotAllOauthTokenReturned', [countResult.totalSize, tokenResult.totalSize])
        );
      }
      return tokenResult.records;
    }
  }

  private async batchQueryTokens(options: QueryOptions): Promise<SfOauthToken[]> {
    const userIds = await this.fetchUserIds();
    const queryPromises: Array<Promise<SfOauthToken[]>> = [];
    const userIdChunks = chunkUserIds(userIds, options.startingBatchSize);
    for (const idChunk of userIdChunks) {
      queryPromises.push(this.fetchTokenChunk(idChunk, options));
    }
    const results = await Promise.all(queryPromises);
    const tokens: SfOauthToken[] = [];
    for (const result of results) {
      tokens.push(...result);
    }
    return tokens;
  }

  private async fetchTokenChunk(userIds: string[], options: QueryOptions): Promise<SfOauthToken[]> {
    const tokens: SfOauthToken[] = [];
    const countResult = await this.con.query(formatCountSoql(userIds));
    if (countResult.totalSize > options.totalSizeThreshold && options.startingBatchSize > 1) {
      const reducedChunkSize = Math.floor(options.startingBatchSize / 2);
      const subChunks = chunkUserIds(userIds, reducedChunkSize);
      const subResultProms: Array<Promise<SfOauthToken[]>> = [];
      for (const subChunk of subChunks) {
        subResultProms.push(
          this.fetchTokenChunk(subChunk, {
            totalSizeThreshold: options.totalSizeThreshold,
            startingBatchSize: reducedChunkSize,
          })
        );
      }
      const subResults = await Promise.all(subResultProms);
      for (const subResult of subResults) {
        tokens.push(...subResult);
      }
    } else {
      const direktResult = await this.con.query<SfOauthToken>(formatTokenSoql(userIds));
      tokens.push(...direktResult.records);
    }
    return tokens;
  }

  private async fetchUserIds(): Promise<string[]> {
    const userResult = await this.con.query<SfMinimalUser>(ALL_EXISTING_USER_IDS);
    return userResult.records.map((userRecord) => userRecord.Id);
  }
}

function chunkUserIds(userIds: string[], chunkSize: number): string[][] {
  const chunks = [];
  for (let i = 0; i < userIds.length; i += chunkSize) {
    chunks.push(userIds.slice(i, i + chunkSize));
  }
  return chunks;
}
