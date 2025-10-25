/* eslint-disable camelcase */
import path from 'node:path';
import { expect } from 'chai';
import { Messages } from '@salesforce/core';
import AuditTestContext, { buildResultsPath } from '../../mocks/auditTestContext.js';
import { BasePolicyFileContent } from '../../../src/libs/core/file-mgmt/schema.js';
import ConnectedAppPolicy from '../../../src/libs/policies/connectedAppPolicy.js';
import { CONNECTED_APPS_QUERY, OAUTH_TOKEN_QUERY } from '../../../src/libs/config/queries.js';
import { ResolvedConnectedApp } from '../../../src/libs/core/registries/connectedApps.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const RETRIEVE_DIR = path.join('test', 'mocks', 'data', 'retrieves', 'connected-app-settings');

const DEFAULT_CONFIG = {
  enabled: true,
  rules: {
    AllUsedAppsUnderManagement: {
      enabled: false,
    },
    NoUserCanSelfAuthorize: {
      enabled: false,
    },
  },
} as BasePolicyFileContent;

describe('connected apps policy', () => {
  const $$ = new AuditTestContext();

  beforeEach(async () => {
    await $$.init();
  });

  afterEach(async () => {
    $$.reset();
  });

  it('resolves all apps from ConnectedApplication and OauthToken', async () => {
    // Arrange
    $$.mocks.setQueryMock(CONNECTED_APPS_QUERY, buildResultsPath('connected-apps'));
    $$.mocks.setQueryMock(OAUTH_TOKEN_QUERY, buildResultsPath('oauth-usage'));

    // Act
    const pol = new ConnectedAppPolicy(DEFAULT_CONFIG, $$.mockAuditConfig);
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
    $$.mocks.setQueryMock(CONNECTED_APPS_QUERY, buildResultsPath('connected-apps'));
    const conf = structuredClone(DEFAULT_CONFIG);
    conf.rules.NoUserCanSelfAuthorize.enabled = true;

    // Act
    const pol = new ConnectedAppPolicy(conf, $$.mockAuditConfig);
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
    ]);
    expect(policyResult.isCompliant).to.equal(true);
    const executedRuleNames = Object.keys(policyResult.executedRules);
    expect(executedRuleNames).to.deep.equal(['NoUserCanSelfAuthorize']);
  });

  it('gracefully handles if ApiAccess setting is not available on org', async () => {
    // Arrange
    $$.mocks.setQueryMock(CONNECTED_APPS_QUERY, buildResultsPath('connected-apps'));
    $$.mockAppSetting = path.join(RETRIEVE_DIR, 'api-security-controls-not-available.xml');
    const conf = structuredClone(DEFAULT_CONFIG);
    conf.rules.NoUserCanSelfAuthorize.enabled = true;

    // Act
    const pol = new ConnectedAppPolicy(conf, $$.mockAuditConfig);
    const resolveResult = await pol.resolve({ targetOrgConnection: await $$.targetOrg.getConnection() });
    const policyResult = await pol.run({ targetOrgConnection: await $$.targetOrg.getConnection() });

    // Assert
    expect(resolveResult.ignoredEntities).to.deep.equal([]);
    expect(Object.keys(resolveResult.resolvedEntities).length).to.equal(5);
    Object.values(resolveResult.resolvedEntities).forEach((appConf) => {
      const resolvedApp = appConf as ResolvedConnectedApp;
      expect(resolvedApp.overrideByApiSecurityAccess).to.be.false;
    });
    const executedRuleNames = Object.keys(policyResult.executedRules);
    expect(executedRuleNames).to.deep.equal(['NoUserCanSelfAuthorize']);
  });
});
