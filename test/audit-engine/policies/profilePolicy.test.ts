import { expect, assert } from 'chai';
import { Messages } from '@salesforce/core';
import AuditTestContext from '../../mocks/auditTestContext.js';
import {
  PermissionRiskLevel,
  PolicyConfig,
  ProfileClassifications,
  UserPrivilegeLevel,
} from '../../../src/libs/audit-engine/registry/shape/schema.js';
import { resolveAndRun } from '../../mocks/testHelpers.js';
import { createDigest } from '../../../src/utils.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policies.general');
const ruleMessages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.enforceClassificationPresets');
const ipRangesMessages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.enforceLoginIpRanges');

describe('policy - profiles', () => {
  const $$ = new AuditTestContext();
  let defaultConfig: PolicyConfig;

  beforeEach(async () => {
    $$.mockAuditConfig.classifications = {
      profiles: {
        profiles: {
          'System Administrator': {
            role: UserPrivilegeLevel.ADMIN,
          },
          'Standard User': {
            role: UserPrivilegeLevel.STANDARD_USER,
          },
          'Custom Profile': {
            role: UserPrivilegeLevel.POWER_USER,
          },
        },
      },
    };
    defaultConfig = {
      enabled: true,
      rules: {
        EnforcePermissionClassifications: {
          enabled: true,
        },
      },
    };
    $$.mockAuditConfig.policies.profiles = defaultConfig;
    await $$.init();
  });

  afterEach(async () => {
    $$.reset();
  });

  describe('entity resolve', () => {
    it('ignores profiles from config where metadata is not resolved from target org', async () => {
      // Arrange
      defaultConfig.rules = {};

      // Act
      const policyResult = await resolveAndRun('profiles', $$);

      // Assert
      expect(policyResult.ignoredEntities).to.deep.equal([
        { name: 'Custom Profile', message: messages.getMessage('profile-invalid-no-metadata') },
      ]);
      expect(policyResult.auditedEntities).to.deep.equal(['System Administrator', 'Standard User']);
    });

    it('ignores profile from config that does not exist on target org', async () => {
      // Arrange
      defaultConfig.rules = {};
      $$.mocks.mockProfiles('admin-and-standard-profiles');

      // Act
      const policyResult = await resolveAndRun('profiles', $$);

      // Assert
      // this used to be "no metadata" error message, but moving the logic to
      // mdapi retriever removed visibility into WHY a profile does not resolve
      // for future release, this could be added back as "resolve entity events"
      expect(policyResult.ignoredEntities[0]).to.deep.equal({
        name: 'Custom Profile',
        message: messages.getMessage('entity-not-found'),
      });
      expect(policyResult.auditedEntities).to.deep.equal(['System Administrator', 'Standard User']);
    });

    it('ignores profiles with UNKNOWN preset without attempting to resolve', async () => {
      // Arrange
      defaultConfig.rules = {};
      $$.mockProfileClassification('Custom Profile', { role: UserPrivilegeLevel.UNKNOWN });

      // Act
      const policyResult = await resolveAndRun('profiles', $$);

      // Assert
      expect(policyResult.ignoredEntities).to.deep.equal([
        { name: 'Custom Profile', message: messages.getMessage('preset-unknown', ['Profile']) },
      ]);
      expect(policyResult.auditedEntities).to.deep.equal(['System Administrator', 'Standard User']);
    });

    it('resolves profiles on target org and warns they are not classified', async () => {
      // Arrange
      $$.mockProfileClassifications({
        'System Administrator': {
          role: UserPrivilegeLevel.ADMIN,
        },
        'Standard User': {
          role: UserPrivilegeLevel.STANDARD_USER,
        },
      });

      // Act
      const policyResult = await resolveAndRun('profiles', $$);

      // Assert
      // default query returns 3 profiles, but only 2 are classified
      expect(policyResult.ignoredEntities.length).to.equal(1);
      for (const ignoredEntity of policyResult.ignoredEntities) {
        expect(ignoredEntity.message).to.equal(messages.getMessage('entity-not-classified'));
      }
      // the profiles that are classified and retrieved
      expect(policyResult.auditedEntities).to.deep.equal(['System Administrator', 'Standard User']);
    });
  });

  describe('rule execution', () => {
    describe('EnforcePermissionClassifications', () => {
      it('reports error in custom perms if permission classification does not match preset', async () => {
        // Arrange
        defaultConfig.rules.EnforcePermissionClassifications.enabled = true;
        $$.mockAuditConfig.classifications.customPermissions = {
          permissions: {
            CriticalCustomPermission: { classification: PermissionRiskLevel.CRITICAL },
          },
        };

        // Act
        const policyResult = await resolveAndRun('profiles', $$);

        // Assert
        expect(policyResult.isCompliant).to.equal(false);
        const executedRuleNames = Object.keys(policyResult.executedRules);
        expect(executedRuleNames).to.deep.equal(['EnforcePermissionClassifications']);
        assert.isDefined(policyResult.executedRules.EnforcePermissionClassifications);
        expect(policyResult.executedRules.EnforcePermissionClassifications.isCompliant).to.be.false;
        expect(policyResult.executedRules.EnforcePermissionClassifications.violations).to.deep.equal([
          {
            identifier: ['Standard User', 'CriticalCustomPermission'],
            message: ruleMessages.getMessage('violations.classification-preset-mismatch', [
              'Critical',
              'Standard User',
            ]),
          },
        ]);
      });
    });

    describe('EnforceLoginIpRanges', () => {
      let ruleConfig: PolicyConfig;
      let classifications: ProfileClassifications;
      const digest127 = createDigest('127.0.0.1-127.0.0.255');
      const digest255 = createDigest('255.255.255.1-255.255.255.255');
      const digest0 = createDigest('0.0.0.0-1.1.1.1');

      beforeEach(() => {
        ruleConfig = {
          enabled: true,
          rules: {
            EnforceLoginIpRanges: {
              enabled: true,
            },
          },
        };
        classifications = {
          'System Administrator': {
            role: UserPrivilegeLevel.ADMIN,
            allowedLoginIps: [
              { from: '127.0.0.1', to: '127.0.0.255' },
              { from: '255.255.255.1', to: '255.255.255.255' },
            ],
          },
          'Standard User': {
            role: UserPrivilegeLevel.STANDARD_USER,
          },
        };
        $$.mockAuditConfig.policies.profiles = ruleConfig;
        $$.mockAuditConfig.classifications.profiles = { profiles: classifications };
      });

      it('reports violation if profile does not have required login IP ranges', async () => {
        // Act
        const result = await resolveAndRun('profiles', $$);

        // Assert
        const ruleResult = result.executedRules.EnforceLoginIpRanges;
        assert.isDefined(ruleResult);
        expect(ruleResult.violations).to.deep.equal([
          {
            identifier: ['System Administrator', digest127],
            message: ipRangesMessages.getMessage('violation.profile-requires-ip-ranges', ['127.0.0.1 - 127.0.0.255']),
          },
          {
            identifier: ['System Administrator', digest255],
            message: ipRangesMessages.getMessage('violation.profile-requires-ip-ranges', [
              '255.255.255.1 - 255.255.255.255',
            ]),
          },
        ]);
      });

      it('reports no violation if profile exactly matches required login IP ranges', async () => {
        // Arrange
        $$.mocks.mockProfileResolve('System Administrator', 'admin-profile-with-ip-ranges');

        // Act
        const result = await resolveAndRun('profiles', $$);

        // Assert
        const ruleResult = result.executedRules.EnforceLoginIpRanges;
        assert.isDefined(ruleResult);
        expect(ruleResult.violations).to.deep.equal([]);
      });

      it('reports violation if profile matches required login IP ranges partially', async () => {
        // Arrange
        classifications['System Administrator'].allowedLoginIps?.push({ from: '0.0.0.0', to: '1.1.1.1' });
        $$.mocks.mockProfileResolve('System Administrator', 'admin-profile-with-ip-ranges');

        // Act
        const result = await resolveAndRun('profiles', $$);

        // Assert
        const ruleResult = result.executedRules.EnforceLoginIpRanges;
        assert.isDefined(ruleResult);
        const expectedViolationDetails = [
          '127.0.0.1 - 127.0.0.255 (Mock home address)',
          '255.255.255.1 - 255.255.255.255 (Mock VPN address)',
        ];
        expect(ruleResult.violations).to.deep.equal([
          {
            identifier: ['System Administrator', digest0],
            message: ipRangesMessages.getMessage('violation.profile-ip-ranges-do-not-satisfy', [
              '0.0.0.0 - 1.1.1.1',
              expectedViolationDetails.length,
            ]),
            details: expectedViolationDetails,
          },
        ]);
      });

      it('reports no violation if profile has IP ranges but none are required', async () => {
        // Arrange
        $$.mocks.mockProfileResolve('System Administrator', 'admin-profile-with-ip-ranges');

        // Act
        const result = await resolveAndRun('profiles', $$);

        // Assert
        const ruleResult = result.executedRules.EnforceLoginIpRanges;
        assert.isDefined(ruleResult);
        expect(ruleResult.isCompliant).to.be.true;
      });

      it('reports violation if profile allows more IP ranges and strict matching is enabled', async () => {
        // Arrange
        ruleConfig.rules.EnforceLoginIpRanges.options = { noExcessiveRanges: true };
        classifications['System Administrator'].allowedLoginIps = [{ from: '127.0.0.1', to: '127.0.0.255' }];
        $$.mocks.mockProfileResolve('System Administrator', 'admin-profile-with-ip-ranges');

        // Act
        const result = await resolveAndRun('profiles', $$);

        // Assert
        const ruleResult = result.executedRules.EnforceLoginIpRanges;
        assert.isDefined(ruleResult);
        expect(ruleResult.violations).to.deep.equal([
          {
            identifier: ['System Administrator', digest255],
            message: ipRangesMessages.getMessage('violation.profile-allows-excessive-range', [
              '255.255.255.1 - 255.255.255.255 (Mock VPN address)',
            ]),
          },
        ]);
      });

      it('reports no violation if profile allows more IP ranges and strict ranges are disabled', async () => {
        // Arrange
        ruleConfig.rules.EnforceLoginIpRanges.options = { noExcessiveRanges: false };
        classifications['System Administrator'].allowedLoginIps = [{ from: '127.0.0.1', to: '127.0.0.255' }];
        $$.mocks.mockProfileResolve('System Administrator', 'admin-profile-with-ip-ranges');

        // Act
        const result = await resolveAndRun('profiles', $$);

        // Assert
        const ruleResult = result.executedRules.EnforceLoginIpRanges;
        assert.isDefined(ruleResult);
        expect(ruleResult.violations).to.deep.equal([]);
      });
    });
  });
});
