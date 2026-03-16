import { expect, assert } from 'chai';
import { Messages } from '@salesforce/core';
import { ConnectedApps, ResolveLifecycle } from '../../src/salesforce/index.js';
import AuditTestContext from '../mocks/auditTestContext.js';
import OAuthTokens from '../../src/salesforce/repositories/connected-apps/oauth-tokens.js';
import { SfMinimalUser, SfOauthToken } from '../../src/salesforce/repositories/connected-apps/connected-app.types.js';
import { OAUTH_TOKEN_QUERY } from '../../src/salesforce/repositories/connected-apps/queries.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'metadataretrieve');

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
    await $$.init();
    $$.mocks.mockOAuthTokenRecords(mockTokens);
    $$.mocks.mockUserRecords(mockUsers);
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
    const apps = await repo.resolve({ withTokenUsage: true });

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

  it('emits warning if total user count exceeds autoFetch limit', async () => {
    // Arrange
    process.env['SAE_MAX_USERS_LIMIT'] = '2500';
    const warnListener = $$.context.SANDBOX.stub();
    ResolveLifecycle.on('resolvewarning', warnListener);
    const users = generateMockUsers(3000);
    const tokens = generateMockTokens(users.length, NUMBER_OF_APPS);
    $$.mocks.mockUserRecords(users);
    $$.mocks.mockOAuthTokenRecords(tokens);
    prepareMocksForUserChunks(tokens, users, USER_IDS_BATCH_SIZE, NUMBER_OF_APPS);
    $$.mocks.fullQueryResults['0r8000000000000AAA-2000'] = {
      done: true,
      records: users.slice(2000),
      totalSize: 3000,
    };

    // Act
    const tokenRepo = new OAuthTokens($$.targetOrgConnection);
    const queriedTokens = await tokenRepo.queryAll({
      totalSizeThreshold: 20,
      startingBatchSize: USER_IDS_BATCH_SIZE,
    });

    // Assert
    const expectedTokenCount = 2500 * NUMBER_OF_APPS;
    expect(warnListener.args.flat()).to.deep.equal([
      {
        message: messages.getMessage('warning.TooManyUsersIncreaseLimit', [3000, 2500]),
      },
      {
        message: messages.getMessage('warning.NotAllOauthTokenReturned', [15_000, expectedTokenCount]),
      },
    ]);
    expect(queriedTokens).to.have.lengthOf(expectedTokenCount);
  });

  it('matches token to app by Id even if app names do not match', async () => {
    // Arrange
    // there appear to be rare cases where label of connectedApp does not
    // match the "AppName" in token usage. Since AppMenuItem is only populated
    // for installed connected apps, we still need to match by AppName as fallback
    $$.mocks.mockOAuthTokens('oauth-usage-name-mismatch');
    $$.mocks.mockConnectedApps('connected-apps');

    // Act
    const appsRepo = new ConnectedApps($$.targetOrgConnection);
    const apps = await appsRepo.resolve({ withTokenUsage: true });

    // Assert
    expect(apps.size).to.equal(6);
    assert.isUndefined(apps.get('Should be Test App 1'));
    const app1 = apps.get('Test App 1');
    assert.isDefined(app1);
    expect(app1.useCount).to.equal(1);
    expect(app1.origin).to.equal('Installed');
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
