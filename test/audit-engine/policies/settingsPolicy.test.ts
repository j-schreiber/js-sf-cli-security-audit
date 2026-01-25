/* eslint-disable camelcase */
import { expect } from 'chai';
import { Messages } from '@salesforce/core';
import AuditTestContext from '../../mocks/auditTestContext.js';
import SettingsPolicy, { SettingsRuleRegistry } from '../../../src/libs/audit-engine/registry/policies/settings.js';
import { PolicyConfig } from '../../../src/libs/audit-engine/registry/shape/schema.js';
import EnforceSettings from '../../../src/libs/audit-engine/registry/rules/enforceSettings.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policies.general');
const ruleMessages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.settings');

describe('settings policy', () => {
  const $$ = new AuditTestContext();
  let defaultConfig: PolicyConfig;

  beforeEach(async () => {
    defaultConfig = {
      enabled: true,
      rules: {
        EnforceSecuritySettings: {
          enabled: true,
          options: {
            enableAdminLoginAsAnyUser: true,
          },
        },
        EnforceApexSettings: {
          enabled: true,
          options: {
            enableApexAccessRightsPref: true,
          },
        },
      },
    };
    $$.mockAuditConfig.policies.settings = defaultConfig;
    await $$.init();
  });

  afterEach(async () => {
    $$.reset();
  });

  describe('registry rule resolution', () => {
    it('recognizes all rules that follow naming convention as valid rules', async () => {
      // Arrange
      const rules = {
        EnforceSecuritySettings: {
          enabled: true,
        },
        EnforceApexSettings: {
          enabled: true,
        },
        EnforceUserInterfaceSettings: {
          enabled: false,
        },
      };

      // Act
      const ruleResolveResult = new SettingsRuleRegistry().resolveRules(rules, $$.mockAuditConfig);

      // Assert
      expect(ruleResolveResult.resolveErrors).to.deep.equal([]);
      expect(ruleResolveResult.skippedRules).to.deep.equal([
        { name: 'EnforceUserInterfaceSettings', skipReason: messages.getMessage('skip-reason.rule-not-enabled') },
      ]);
      expect(ruleResolveResult.enabledRules.length).to.equal(2);
      expect(ruleResolveResult.enabledRules[0]).to.deep.equal(
        new EnforceSettings({
          ruleDisplayName: 'EnforceSecuritySettings',
          ruleConfig: {},
          settingName: 'Security',
          auditConfig: $$.mockAuditConfig,
        })
      );
    });

    it('ignores rules that do not follow naming convention', () => {
      // Arrange
      const rules = {
        SomeNonSettings: {
          enabled: true,
        },
        EnforceSomething: {
          enabled: true,
        },
        CompletelyOffBase: {
          enabled: true,
        },
      };

      // Act
      const ruleResolveResult = new SettingsRuleRegistry().resolveRules(rules, $$.mockAuditConfig);

      // Assert
      expect(ruleResolveResult.skippedRules).to.deep.equal([
        { name: 'SomeNonSettings', skipReason: messages.getMessage('resolve-error.no-valid-settings-rule') },
        { name: 'EnforceSomething', skipReason: messages.getMessage('resolve-error.no-valid-settings-rule') },
        { name: 'CompletelyOffBase', skipReason: messages.getMessage('resolve-error.no-valid-settings-rule') },
      ]);
      expect(ruleResolveResult.resolveErrors).to.deep.equal([]);
      expect(ruleResolveResult.enabledRules).to.deep.equal([]);
    });

    it('accepts any rule config that is a valid record and passes it through', () => {
      // Arrange
      const rules = {
        EnforceSecuritySettings: {
          enabled: true,
          options: {
            enableAdminLoginAsAnyUser: true,
            passwordPolicies: {
              minimumPasswordLifetime: true,
              expiration: 'OneYear',
              historyRestriction: 3,
            },
            sessionSettings: {
              allowUserAuthenticationByCertificate: false,
              enforceIpRangesEveryRequest: true,
              lockSessionsToIp: true,
            },
          },
        },
      };

      // Act
      const ruleResolveResult = new SettingsRuleRegistry().resolveRules(rules, $$.mockAuditConfig);

      // Assert
      const initialisedRule = ruleResolveResult.enabledRules[0];
      expect(initialisedRule).to.deep.equal(
        new EnforceSettings({
          ruleDisplayName: 'EnforceSecuritySettings',
          auditConfig: $$.mockAuditConfig,
          settingName: 'Security',
          ruleConfig: rules.EnforceSecuritySettings.options,
        })
      );
    });
  });

  describe('resolve policy', () => {
    let resolveListener: ReturnType<(typeof $$)['context']['SANDBOX']['stub']>;

    beforeEach(() => {
      resolveListener = $$.context.SANDBOX.stub();
    });

    function resolve(conf: PolicyConfig): ReturnType<SettingsPolicy['resolve']> {
      const pol = new SettingsPolicy(conf, $$.mockAuditConfig);
      pol.addListener('entityresolve', resolveListener);
      return pol.resolve({ targetOrgConnection: $$.targetOrgConnection });
    }

    it('interprets each valid rule as an entity and resolves them in bulk', async () => {
      // Act
      const result = await resolve(defaultConfig);

      // Assert
      expect(result.ignoredEntities).to.deep.equal([]);
      expect(Object.keys(result.resolvedEntities)).to.have.members(['Security', 'Apex']);
    });

    it('ignores an invalid rule but does not add it to ignoredEntities', async () => {
      // Arrange
      defaultConfig.rules['SomeInvalidRuleName'] = { enabled: true };

      // Act
      const result = await resolve(defaultConfig);

      // Assert
      expect(result.ignoredEntities).to.deep.equal([]);
      expect(Object.keys(result.resolvedEntities)).to.have.members(['Security', 'Apex']);
    });

    it('ignores the entity of a syntactically valid rule that cannot be resolved to a setting', async () => {
      // Arrange
      defaultConfig.rules['EnforceSomeInvalidSettings'] = { enabled: true };

      // Act
      const result = await resolve(defaultConfig);

      // Assert
      expect(result.ignoredEntities).to.deep.equal([
        { message: messages.getMessage('resolve-error.failed-to-resolve-setting'), name: 'SomeInvalid' },
      ]);
      expect(Object.keys(result.resolvedEntities)).to.have.members(['Security', 'Apex']);
    });

    it('gracefully skips policy metadata retrieve if it has no rules', async () => {
      // Act
      const result = await resolve({ enabled: true, rules: {} });

      // Assert
      expect(Object.keys(result.resolvedEntities)).to.deep.equal([]);
      // metadata retrieve fails with an error, if the retrieved component set is empty
      // Error (MetadataApiRetrieveError): No components in the package to retrieve.
      expect($$.mocks.retrieveStub?.callCount).to.equal(0);
    });

    it('skips metadata retrieve of a valid setting if the rule is disabled', async () => {
      // Act
      defaultConfig.rules.EnforceApexSettings.enabled = false;
      const result = await resolve(defaultConfig);

      // Assert
      expect(Object.keys(result.resolvedEntities)).to.deep.equal(['Security']);
      expect(resolveListener.args.flat()).to.deep.equal([
        { resolved: 0, total: 1 },
        { resolved: 1, total: 1 },
      ]);
    });

    it('gracefully skips policy metadata retrieve if rule has invalid name', async () => {
      // Act
      // valid name would be EnforceApexSettings (mind the trailing "s")
      const result = await resolve({ enabled: true, rules: { EnforceApexSetting: { enabled: true } } });

      // Assert
      expect(Object.keys(result.resolvedEntities)).to.deep.equal([]);
      // metadata retrieve fails with an error, if the retrieved component set is empty
      // Error (MetadataApiRetrieveError): No components in the package to retrieve.
      expect($$.mocks.retrieveStub?.callCount).to.equal(0);
    });

    it('correctly reports resolve status for unknown settings on org', async () => {
      // Arrange
      // this stub only returns "ConnectedApp" settings
      await $$.mocks.stubMetadataRetrieve('security-settings');

      // Act
      // config now has three enabled rules
      defaultConfig.rules['EnforceConnectedAppSettings'] = { enabled: true };
      const result = await resolve(defaultConfig);

      // Assert
      expect(Object.keys(result.resolvedEntities)).to.deep.equal(['ConnectedApp']);
      expect(result.ignoredEntities).to.have.deep.members([
        { name: 'Security', message: messages.getMessage('resolve-error.failed-to-resolve-setting') },
        { name: 'Apex', message: messages.getMessage('resolve-error.failed-to-resolve-setting') },
      ]);
      expect(resolveListener.args.flat()).to.deep.equal([
        { resolved: 0, total: 3 },
        { resolved: 1, total: 3 },
      ]);
    });
  });

  describe('run policy', () => {
    it('resolves settings for valid rules and enforces plain setting options', async () => {
      // Act
      const pol = new SettingsPolicy(defaultConfig, $$.mockAuditConfig);
      const result = await pol.run({ targetOrgConnection: $$.targetOrgConnection });

      // Assert
      expect(Object.keys(result.executedRules)).to.deep.equal(['EnforceSecuritySettings', 'EnforceApexSettings']);
      const secResult = result.executedRules.EnforceSecuritySettings;
      expect(secResult.isCompliant).to.be.true;
      expect(secResult.compliantEntities).to.deep.equal(['SecuritySettings']);
      expect(secResult.violatedEntities).to.deep.equal([]);
      const apexResult = result.executedRules.EnforceApexSettings;
      expect(apexResult.isCompliant).to.be.true;
      expect(apexResult.compliantEntities).to.deep.equal(['ApexSettings']);
      expect(apexResult.violatedEntities).to.deep.equal([]);
    });

    it('resolves settings for valid rules and traverses nested setting options', async () => {
      // Arrange
      const config = {
        enabled: true,
        rules: {
          EnforceSecuritySettings: {
            enabled: true,
            options: {
              passwordPolicies: {
                minimumPasswordLength: 12,
              },
              sessionSettings: {
                canConfirmIdentityBySmsOnly: false,
                lockSessionsToIp: true,
              },
            },
          },
        },
      };

      // Act
      const pol = new SettingsPolicy(config, $$.mockAuditConfig);
      const result = await pol.run({ targetOrgConnection: $$.targetOrgConnection });

      // Assert
      const secResult = result.executedRules.EnforceSecuritySettings;
      expect(secResult.isCompliant).to.be.false;
      expect(secResult.compliantEntities).to.deep.equal([]);
      expect(secResult.warnings).to.deep.equal([]);
      expect(secResult.violations[0]).to.deep.equal({
        identifier: ['SecuritySettings', 'passwordPolicies', 'minimumPasswordLength'],
        message: ruleMessages.getMessage('violations.expected-value-does-not-match', [12, 10]),
      });
      expect(secResult.violations[1]).to.deep.equal({
        identifier: ['SecuritySettings', 'sessionSettings', 'canConfirmIdentityBySmsOnly'],
        message: ruleMessages.getMessage('violations.expected-value-does-not-match', [false, true]),
      });
      expect(secResult.violations[2]).to.deep.equal({
        identifier: ['SecuritySettings', 'sessionSettings', 'lockSessionsToIp'],
        message: ruleMessages.getMessage('violations.expected-value-does-not-match', [true, false]),
      });
    });

    it('ignores invalid settings keys and logs a warning', async () => {
      // Arrange
      defaultConfig.rules.EnforceApexSettings.options = {
        anUnknownSettingKey: true,
      };

      // Act
      const pol = new SettingsPolicy(defaultConfig, $$.mockAuditConfig);
      const result = await pol.run({ targetOrgConnection: $$.targetOrgConnection });

      // Assert
      const apexResult = result.executedRules.EnforceApexSettings;
      expect(apexResult.isCompliant).to.be.true;
      expect(apexResult.compliantEntities).to.deep.equal(['ApexSettings']);
      expect(apexResult.warnings).to.deep.equal([
        {
          identifier: ['ApexSettings', 'anUnknownSettingKey'],
          message: ruleMessages.getMessage('warnings.property-does-not-exist'),
        },
      ]);
      const secResult = result.executedRules.EnforceSecuritySettings;
      expect(secResult.compliantEntities).to.deep.equal(['SecuritySettings']);
    });

    it('reports a rule that does not follow naming conventions as skippedRule', async () => {
      // Arrange
      defaultConfig.rules = {
        ApexSettings: {
          enabled: true,
        },
      };

      // Act
      const pol = new SettingsPolicy(defaultConfig, $$.mockAuditConfig);
      const result = await pol.run({ targetOrgConnection: $$.targetOrgConnection });

      // Assert
      expect(result.skippedRules).to.deep.equal([
        { name: 'ApexSettings', skipReason: messages.getMessage('resolve-error.no-valid-settings-rule') },
      ]);
      expect(result.ignoredEntities).to.deep.equal([]);
    });

    it('reports a rule that does not resolve to a valid setting as skipped', async () => {
      // Act
      const pol = new SettingsPolicy(
        {
          enabled: true,
          rules: {
            EnforceInvalidSettings: { enabled: true },
            EnforceApexSettings: { enabled: true },
            EnforceOtherInvalidSettings: { enabled: true },
          },
        },
        $$.mockAuditConfig
      );
      const result = await pol.run({ targetOrgConnection: $$.targetOrgConnection });

      // Assert
      expect(result.auditedEntities).to.deep.equal(['Apex']);
      expect(Object.keys(result.executedRules)).to.deep.equal(['EnforceApexSettings']);
      expect(result.skippedRules).to.deep.equal([
        {
          name: 'EnforceInvalidSettings',
          skipReason: messages.getMessage('skip-reason.failed-to-resolve-setting', ['Invalid']),
        },
        {
          name: 'EnforceOtherInvalidSettings',
          skipReason: messages.getMessage('skip-reason.failed-to-resolve-setting', ['OtherInvalid']),
        },
      ]);
    });
  });
});
