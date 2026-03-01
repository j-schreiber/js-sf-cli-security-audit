import { expect, assert } from 'chai';
import { ConnectedApps } from '../../src/salesforce/index.js';
import AuditTestContext from '../mocks/auditTestContext.js';
import OAuthTokens from '../../src/salesforce/repositories/connected-apps/oauth-tokens.js';
import { SfMinimalUser, SfOauthToken } from '../../src/salesforce/repositories/connected-apps/connected-app.types.js';
import { OAUTH_TOKEN_QUERY } from '../../src/salesforce/repositories/connected-apps/queries.js';

describe('connected apps resolve', () => {
  const $$ = new AuditTestContext();
  const USER_IDS_BATCH_SIZE = 4;
  const NUMBER_OF_APPS = 5;
  const mockTokens = generateMockTokens(100, NUMBER_OF_APPS);
  const mockUsers = generateMockUsers(100);

  /**
   * Users ordered lists of all tokens and all users to prepare chunk-mocks
   *
   * @param allTokens
   * @param allUsers
   * @param chunkSize
   */
  function prepareMocksForUserChunks(
    allTokens: SfOauthToken[],
    allUsers: SfMinimalUser[],
    chunkSize: number,
    numberOfAppsPerUser: number
  ): void {
    for (let i = 0; i < allUsers.length; i += chunkSize) {
      const userIdsChunk = allUsers.slice(i, i + chunkSize).map((user) => user.Id);
      $$.mocks.mockFilteredTokenRecords(
        userIdsChunk,
        allTokens.slice(i * numberOfAppsPerUser, (i + chunkSize) * numberOfAppsPerUser)
      );
    }
  }

  beforeEach(async () => {
    $$.mocks.mockOAuthTokenRecords(mockTokens);
    $$.mocks.mockUserRecords(mockUsers);
    await $$.init();
  });

  afterEach(async () => {
    $$.reset();
  });

  /**
   * As it turns out, OAuthToken does NOT support nextRecordsUrl. Therefore,
   * autofetch functionality does not work for results larger than 2500.
   */
  it('queries tokens with autoFetch when results are too large', async () => {
    // Arrange
    $$.mocks.setFullQueryResult(OAUTH_TOKEN_QUERY, 'oauth-usage-not-done');
    $$.mocks.setFullQueryResult('0r8xx3d3FsAvwqKAIR-5', 'oauth-usage-completed');

    // Act
    const repo = new ConnectedApps($$.targetOrgConnection);
    const apps = await repo.resolve({ withOAuthToken: true });

    // Assert
    expect(apps.size).to.equal(3);
    const app1 = apps.get('Test App 1');
    assert.isDefined(app1);
    expect(app1.users).to.deep.equal([
      'test1@example.com',
      'test2@example.com',
      'test3@example.com',
      'test4@example.com',
    ]);
    const app2 = apps.get('Test App 2');
    assert.isDefined(app2);
    expect(app2.users).to.deep.equal(['test1@example.com']);
  });

  it('batches token retrieve by user id when initial count exceeds threshold', async () => {
    // Arrange
    prepareMocksForUserChunks(mockTokens, mockUsers, USER_IDS_BATCH_SIZE, NUMBER_OF_APPS);
    prepareMocksForUserChunks(mockTokens, mockUsers, USER_IDS_BATCH_SIZE / 2, NUMBER_OF_APPS);

    // Act
    const tokenRepo = new OAuthTokens($$.targetOrgConnection);
    const tokens = await tokenRepo.queryAll({
      totalSizeThreshold: 10,
      startingBatchSize: USER_IDS_BATCH_SIZE,
    });

    // Assert
    expect(tokens).to.have.lengthOf(500);
  });

  it('uses ENV variables to parametrize batch retrieval of oauth token', async () => {
    // Arrange
    process.env['SAE_MAX_OAUTH_TOKEN_THRESHOLD'] = '6';
    process.env['SAE_OAUTH_TOKEN_BATCH_SIZE'] = '2';
    // engine will immediately start with user chunks of 2, then break down to 1
    prepareMocksForUserChunks(mockTokens, mockUsers, 2, NUMBER_OF_APPS);
    prepareMocksForUserChunks(mockTokens, mockUsers, 1, NUMBER_OF_APPS);

    // Act
    const tokenRepo = new OAuthTokens($$.targetOrgConnection);
    const tokens = await tokenRepo.queryAll();

    // Assert
    expect(tokens).to.have.lengthOf(500);
  });
});

/**
 * Generates X oauth tokens per user. 100 user and 5 apps create 500 tokens.
 *
 * @param userCount
 * @param appCount
 * @returns
 */
function generateMockTokens(userCount: number, appCount: number): SfOauthToken[] {
  const tokens: SfOauthToken[] = [];
  let tokenCounter = 0;
  for (let userIncrementer = 0; userIncrementer < userCount; userIncrementer++) {
    for (let appIncrementer = 0; appIncrementer < appCount; appIncrementer++) {
      tokens.push({
        Id: `token-id-${tokenCounter++}`,
        User: { Username: `test-user-${userIncrementer}@example.com` },
        AppName: `Test App ${appIncrementer}`,
        UseCount: 1,
      });
    }
  }
  return tokens;
}

/**
 * Generates N mock users with syntactically valid user ids
 *
 * @param userCount
 */
function generateMockUsers(userCount: number): SfMinimalUser[] {
  const users: SfMinimalUser[] = [];
  for (let userIncrementer = 0; userIncrementer < userCount; userIncrementer++) {
    users.push({ Id: `005${userIncrementer.toString().padStart(12, '0')}AAA` });
  }
  return users;
}
