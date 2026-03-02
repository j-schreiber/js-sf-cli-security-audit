/* eslint-disable camelcase */
import { expect, assert } from 'chai';
import { Messages } from '@salesforce/core';
import AuditTestContext from '../../mocks/auditTestContext.js';
import { loadPolicy } from '../../../src/libs/audit-engine/index.js';
import { PolicyConfig } from '../../../src/libs/audit-engine/registry/shape/schema.js';
import { resolveAndRun } from '../../mocks/testHelpers.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);

describe('policy - connected apps', () => {
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

  describe('entity resolve', () => {
    it('resolves all apps from ConnectedApplication and OauthToken', async () => {
      // Arrange
      $$.mocks.mockOAuthTokens('oauth-usage');

      // Act
      const policyResult = await resolveAndRun('connectedApps', $$);

      // Assert
      expect(policyResult.ignoredEntities).to.deep.equal([]);
      expect(policyResult.auditedEntities).to.deep.equal([
        'Chatter Desktop',
        'Salesforce for Android',
        'Chatter Mobile for BlackBerry',
        'Salesforce for iOS',
        'Test App 1',
        'Test App 2',
        'AI Platform Auth',
        'Test External Client App',
      ]);
      expect(policyResult.isCompliant).to.equal(true);
      const executedRuleNames = Object.keys(policyResult.executedRules);
      expect(executedRuleNames).to.deep.equal([]);
    });

    it('uses result form ApiAccess setting to override self-authorize flag', async () => {
      // Arrange
      await $$.mocks.stubMetadataRetrieve('security-settings');
      defaultConfig.rules.NoUserCanSelfAuthorize.enabled = true;

      // Act
      const policyResult = await resolveAndRun('connectedApps', $$);

      // Assert
      expect(policyResult.ignoredEntities).to.deep.equal([]);
      expect(policyResult.auditedEntities).to.deep.equal([
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
      await $$.mocks.stubMetadataRetrieve('api-access-not-available');
      defaultConfig.rules.NoUserCanSelfAuthorize.enabled = true;

      // Act
      const pol = loadPolicy('connectedApps', $$.mockAuditConfig);
      const resolveResult = await pol.resolve({ targetOrgConnection: $$.targetOrgConnection });

      // Assert
      expect(resolveResult.ignoredEntities).to.deep.equal([]);
      expect(Object.keys(resolveResult.resolvedEntities)).to.have.lengthOf(5);
      Object.values(resolveResult.resolvedEntities).forEach((appConf) => {
        const resolvedApp = appConf;
        expect(resolvedApp.overrideByApiSecurityAccess).to.be.false;
      });
    });

    it('does not identify external client app as oauth token source', async () => {
      // Arrange
      $$.mocks.mockOAuthTokens('oauth-usage');
      $$.mocks.mockExternalClientApps('external-client-apps');
      $$.mocks.mockExternalClientAppOAuthPolicies('external-client-apps-oauth-policies');

      // Act
      const pol = loadPolicy('connectedApps', $$.mockAuditConfig);
      const resolveResult = await pol.resolve({ targetOrgConnection: $$.targetOrgConnection });

      // Assert
      const externalApp1 = resolveResult.resolvedEntities['Test External Client App'];
      assert.isDefined(externalApp1);
      expect(externalApp1.origin).to.equal('Owned');
      expect(externalApp1.type).to.equal('ExternalClientApp');
      expect(externalApp1.onlyAdminApprovedUsersAllowed).to.be.false;
      expect(externalApp1.useCount).to.equal(10);
      const externalApp2 = resolveResult.resolvedEntities['Ext App 2'];
      assert.isDefined(externalApp2);
      expect(externalApp2.type).to.equal('ExternalClientApp');
      expect(externalApp2.origin).to.equal('Owned');
      expect(externalApp2.onlyAdminApprovedUsersAllowed).to.be.true;
      expect(externalApp2.useCount).to.equal(0);
    });

    it('resolves external app as admin approved false if no oauth scope explicitly defines it', async () => {
      // Arrange
      $$.mocks.mockExternalClientApps('external-client-apps');

      // Act
      const pol = loadPolicy('connectedApps', $$.mockAuditConfig);
      const resolveResult = await pol.resolve({ targetOrgConnection: $$.targetOrgConnection });

      // Assert
      const externalApps = Object.values(resolveResult.resolvedEntities).filter(
        (app) => app.type === 'ExternalClientApp'
      );
      expect(externalApps).to.have.lengthOf(2);
      for (const app of externalApps) {
        expect(app.onlyAdminApprovedUsersAllowed).to.be.false;
      }
    });
  });

  describe('rule execution', () => {
    describe('AllUsedAppsUnderManagement', () => {
      it('adds each user of an app to details of violation', async () => {
        // Arrange
        $$.mocks.mockOAuthTokens('oauth-usage');
        $$.mocks.mockExternalClientApps('external-client-apps');

        // Act
        defaultConfig.rules.AllUsedAppsUnderManagement.enabled = true;
        const policyResult = await resolveAndRun('connectedApps', $$);

        // Assert
        const ruleResult = policyResult.executedRules.AllUsedAppsUnderManagement;
        expect(ruleResult.isCompliant).to.be.false;
        expect(ruleResult.violations).to.have.lengthOf(2);
        expect(ruleResult.violations.at(0)).to.deep.contain({
          identifier: ['Test App 2'],
          details: ['test3@example.com'],
        });
        expect(ruleResult.violations.at(1)).to.deep.contain({
          identifier: ['AI Platform Auth'],
          details: ['cloud@00d3x000001tal2uaa'],
        });
      });
    });
  });
});
