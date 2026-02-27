import { expect, assert } from 'chai';
import { ConnectedApps } from '../../src/salesforce/index.js';
import AuditTestContext from '../mocks/auditTestContext.js';
import { OAUTH_TOKEN_QUERY } from '../../src/salesforce/repositories/connected-apps/oauth-tokens.js';

describe('connected apps resolve', () => {
  const $$ = new AuditTestContext();

  beforeEach(async () => {
    await $$.init();
  });

  afterEach(async () => {
    $$.reset();
  });

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
});
