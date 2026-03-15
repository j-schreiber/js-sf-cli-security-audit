import path from 'node:path';
import { expect } from 'chai';
import Sinon, { SinonSandbox } from 'sinon';
import { AuthInfo, Connection } from '@salesforce/core';
import { TestSession } from '@salesforce/cli-plugins-testkit';
import OAuthTokens from '../../src/salesforce/repositories/connected-apps/oauth-tokens.js';
import { Users } from '../../src/salesforce/index.js';

const testingWorkingDir = path.join('test', 'mocks', 'test-sfdx-project');

describe('salesforce APIs', () => {
  let session: TestSession;
  let orgConnection: Connection;
  const SANDBOX: SinonSandbox = Sinon.createSandbox();

  before(async () => {
    // TestSession prepares the auth files from env variables
    session = await TestSession.create({
      project: {
        sourceDir: testingWorkingDir,
      },
      devhubAuthStrategy: 'AUTO',
    });
    const authInfo = await AuthInfo.create({ username: session.hubOrg.username });
    orgConnection = await Connection.create({ authInfo });
  });

  after(async () => {
    await session?.clean();
    // clean env vars?
  });

  it('queries all oauth tokens in batch fetch and regular fetch', async () => {
    // Arrange
    const warningListener = SANDBOX.mock();
    const tokenRepo = new OAuthTokens(orgConnection);
    tokenRepo.on('resolvewarning', warningListener);

    // Act
    const allTokens = await tokenRepo.queryAll();
    // this will enter recursion down to the bottom of 1 or 2 user records per batch
    // when the org has more than 2 tokens in total. This is always true for my DevHubs.
    const batchedTokens = await tokenRepo.queryAll({ totalSizeThreshold: 2, startingBatchSize: 16 });

    // Assert
    expect(batchedTokens).to.have.lengthOf(allTokens.length);
    expect(warningListener.callCount).to.equal(0);
  });

  it('fetches all users with login history from org', async () => {
    // Act
    const usersRepo = new Users(orgConnection);
    const allUsers = await usersRepo.resolve({ withLoginHistory: true });

    // Assert
    expect(allUsers.size).to.not.equal(0);
    for (const user of allUsers.values()) {
      expect(user.logins).not.to.be.undefined;
    }
  });
});
