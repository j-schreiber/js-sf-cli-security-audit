import { expect } from 'chai';
import Sinon, { SinonSandbox } from 'sinon';
import { AuthInfo, Connection } from '@salesforce/core';
import OAuthTokens from '../../src/salesforce/repositories/connected-apps/oauth-tokens.js';

describe('salesforce APIs', () => {
  let orgConnection: Connection;
  const SANDBOX: SinonSandbox = Sinon.createSandbox();

  before(async () => {
    const testkitUsername = process.env['TESTKIT_HUB_USERNAME'];
    const authInfo = await AuthInfo.create({ username: testkitUsername });
    orgConnection = await Connection.create({ authInfo });
  });

  after(async () => {
    // clean env vars?
  });

  afterEach(async () => {
    // clean audit config files?
  });

  it('retrieves all oauth tokens in batch retrieve and regular retrieve', async () => {
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
});
