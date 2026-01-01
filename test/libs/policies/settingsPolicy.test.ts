/* eslint-disable camelcase */
import { expect } from 'chai';
import { Messages } from '@salesforce/core';
import AuditTestContext from '../../mocks/auditTestContext.js';
import SettingsRegistry from '../../../src/libs/core/registries/settings.js';
import EnforceSettings from '../../../src/libs/core/registries/rules/enforceSettings.js';
import SettingsPolicy from '../../../src/libs/core/policies/settingsPolicy.js';
import { BasePolicyFileContent } from '../../../src/libs/core/file-mgmt/schema.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policies.general');
const ruleMessages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.settings');

const DEFAULT_VALID_CONFIG = {
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
} as BasePolicyFileContent;

describe('settings policy', () => {
  const $$ = new AuditTestContext();

  beforeEach(async () => {
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
      const reg = new SettingsRegistry();
      const ruleResolveResult = reg.resolveRules(rules, $$.mockAuditConfig);

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
          auditContext: $$.mockAuditConfig,
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
      const reg = new SettingsRegistry();
      const ruleResolveResult = reg.resolveRules(rules, $$.mockAuditConfig);

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
      const reg = new SettingsRegistry();
      const ruleResolveResult = reg.resolveRules(rules, $$.mockAuditConfig);

      // Assert
      const initialisedRule = ruleResolveResult.enabledRules[0];
      expect(initialisedRule).to.deep.equal(
        new EnforceSettings({
          ruleDisplayName: 'EnforceSecuritySettings',
          auditContext: $$.mockAuditConfig,
          settingName: 'Security',
          ruleConfig: rules.EnforceSecuritySettings.options,
        })
      );
    });
  });

  describe('resolve policy', () => {
    it('interprets each valid rule as an entity and resolves them in bulk', async () => {
      // Act
      const pol = new SettingsPolicy(DEFAULT_VALID_CONFIG, $$.mockAuditConfig);
      const result = await pol.resolve({ targetOrgConnection: $$.targetOrgConnection });

      // Assert
      expect(result.ignoredEntities).to.deep.equal([]);
      expect(Object.keys(result.resolvedEntities)).to.deep.equal(['Security', 'Apex']);
    });

    it('ignores an invalid rule but does not add it to ignoredEntities', async () => {
      // Arrange
      const confWithInvalidRule = structuredClone(DEFAULT_VALID_CONFIG);
      confWithInvalidRule.rules['SomeInvalidRuleName'] = { enabled: true };

      // Act
      const pol = new SettingsPolicy(confWithInvalidRule, $$.mockAuditConfig);
      const result = await pol.resolve({ targetOrgConnection: $$.targetOrgConnection });

      // Assert
      expect(result.ignoredEntities).to.deep.equal([]);
      expect(Object.keys(result.resolvedEntities)).to.deep.equal(['Security', 'Apex']);
    });

    it('ignores the entity of a syntactically valid rule that cannot be resolved to a setting', async () => {
      // Arrange
      const confWithInvalidRule = structuredClone(DEFAULT_VALID_CONFIG);
      confWithInvalidRule.rules['EnforceSomeInvalidSettings'] = { enabled: true };

      // Act
      const pol = new SettingsPolicy(confWithInvalidRule, $$.mockAuditConfig);
      const result = await pol.resolve({ targetOrgConnection: $$.targetOrgConnection });

      // Assert
      expect(result.ignoredEntities).to.deep.equal([
        { message: messages.getMessage('resolve-error.failed-to-resolve-setting'), name: 'SomeInvalid' },
      ]);
      expect(Object.keys(result.resolvedEntities)).to.deep.equal(['Security', 'Apex']);
    });

    it('gracefully skips policy metadata retrieve if it has no rules', async () => {
      // Act
      const pol = new SettingsPolicy({ enabled: true, rules: {} }, $$.mockAuditConfig);
      const result = await pol.resolve({ targetOrgConnection: $$.targetOrgConnection });

      // Assert
      expect(Object.keys(result.resolvedEntities)).to.deep.equal([]);
      // metadata retrieve fails with an error, if the retrieved component set is empty
      // Error (MetadataApiRetrieveError): No components in the package to retrieve.
      expect($$.retrieveStub?.callCount).to.equal(0);
    });

    it('gracefully skips policy metadata retrieve if rule has invalid name', async () => {
      // Act
      // valid name would be EnforceApexSettings (mind the trailing "s")
      const pol = new SettingsPolicy(
        { enabled: true, rules: { EnforceApexSetting: { enabled: true } } },
        $$.mockAuditConfig
      );
      const result = await pol.resolve({ targetOrgConnection: $$.targetOrgConnection });

      // Assert
      expect(Object.keys(result.resolvedEntities)).to.deep.equal([]);
      // metadata retrieve fails with an error, if the retrieved component set is empty
      // Error (MetadataApiRetrieveError): No components in the package to retrieve.
      expect($$.retrieveStub?.callCount).to.equal(0);
    });
  });

  describe('run policy', () => {
    it('resolves settings for valid rules and enforces plain setting options', async () => {
      // Act
      const pol = new SettingsPolicy(DEFAULT_VALID_CONFIG, $$.mockAuditConfig);
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
      const confWithInvalidOption = structuredClone(DEFAULT_VALID_CONFIG);
      confWithInvalidOption.rules.EnforceApexSettings.options = {
        anUnknownSettingKey: true,
      };

      // Act
      const pol = new SettingsPolicy(confWithInvalidOption, $$.mockAuditConfig);
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
      const confWithInvalidRule = structuredClone(DEFAULT_VALID_CONFIG);
      confWithInvalidRule.rules = {
        ApexSettings: {
          enabled: true,
        },
      };

      // Act
      const pol = new SettingsPolicy(confWithInvalidRule, $$.mockAuditConfig);
      const result = await pol.run({ targetOrgConnection: $$.targetOrgConnection });

      // Assert
      expect(result.skippedRules).to.deep.equal([
        { name: 'ApexSettings', skipReason: messages.getMessage('resolve-error.no-valid-settings-rule') },
      ]);
      expect(result.ignoredEntities).to.deep.equal([]);
    });
  });
});
