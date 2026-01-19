/* eslint-disable camelcase */
import { expect } from 'chai';
import { Messages } from '@salesforce/core';
import AuditTestContext from '../../mocks/auditTestContext.js';
import { loadPolicy } from '../../../src/libs/audit-engine/index.js';
import { PolicyConfig } from '../../../src/libs/audit-engine/registry/shape/schema.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);

describe('connected apps policy', () => {
  const $$ = new AuditTestContext();
  let defaultConfig: PolicyConfig;

  beforeEach(async () => {
    $$.mocks.mockConnectedApps('connected-apps');
    defaultConfig = {
      enabled: true,
      rules: {
        AllUsedAppsUnderManagement: {
          enabled: false,
        },
        NoUserCanSelfAuthorize: {
          enabled: false,
        },
      },
    };
    $$.mockAuditConfig.policies.connectedApps = defaultConfig;
    await $$.init();
  });

  afterEach(async () => {
    $$.reset();
  });

  it('resolves all apps from ConnectedApplication and OauthToken', async () => {
    // Arrange
    $$.mocks.mockOAuthTokens('oauth-usage');

    // Act
    const pol = loadPolicy('connectedApps', $$.mockAuditConfig);
    const resolveResult = await pol.resolve({ targetOrgConnection: await $$.targetOrg.getConnection() });
    const policyResult = await pol.run({ targetOrgConnection: await $$.targetOrg.getConnection() });

    // Assert
    expect(resolveResult.ignoredEntities).to.deep.equal([]);
    expect(Object.keys(resolveResult.resolvedEntities)).to.deep.equal([
      'Chatter Desktop',
      'Salesforce for Android',
      'Chatter Mobile for BlackBerry',
      'Salesforce for iOS',
      'Test App 1',
      'Test App 2',
      'AI Platform Auth',
    ]);
    expect(policyResult.isCompliant).to.equal(true);
    const executedRuleNames = Object.keys(policyResult.executedRules);
    expect(executedRuleNames).to.deep.equal([]);
  });

  it('uses result form ApiAccess setting to override self-authorize flag', async () => {
    // Arrange
    defaultConfig.rules.NoUserCanSelfAuthorize.enabled = true;

    // Act
    const pol = loadPolicy('connectedApps', $$.mockAuditConfig);
    const resolveResult = await pol.resolve({ targetOrgConnection: $$.targetOrgConnection });
    const policyResult = await pol.run({ targetOrgConnection: $$.targetOrgConnection });

    // Assert
    expect(resolveResult.ignoredEntities).to.deep.equal([]);
    expect(Object.keys(resolveResult.resolvedEntities)).to.deep.equal([
      'Chatter Desktop',
      'Salesforce for Android',
      'Chatter Mobile for BlackBerry',
      'Salesforce for iOS',
      'Test App 1',
    ]);
    expect(policyResult.isCompliant).to.equal(true);
    const executedRuleNames = Object.keys(policyResult.executedRules);
    expect(executedRuleNames).to.deep.equal(['NoUserCanSelfAuthorize']);
  });

  it('gracefully handles if ApiAccess setting is not available on org', async () => {
    // Arrange
    $$.mocks.stubMetadataRetrieve('api-access-not-available');
    defaultConfig.rules.NoUserCanSelfAuthorize.enabled = true;

    // Act
    const pol = loadPolicy('connectedApps', $$.mockAuditConfig);
    const resolveResult = await pol.resolve({ targetOrgConnection: $$.targetOrgConnection });
    const policyResult = await pol.run({ targetOrgConnection: $$.targetOrgConnection });

    // Assert
    expect(resolveResult.ignoredEntities).to.deep.equal([]);
    expect(Object.keys(resolveResult.resolvedEntities).length).to.equal(5);
    Object.values(resolveResult.resolvedEntities).forEach((appConf) => {
      const resolvedApp = appConf;
      expect(resolvedApp.overrideByApiSecurityAccess).to.be.false;
    });
    const executedRuleNames = Object.keys(policyResult.executedRules);
    expect(executedRuleNames).to.deep.equal(['NoUserCanSelfAuthorize']);
  });
});
