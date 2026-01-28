import { expect, assert } from 'chai';
import { Connection, Messages } from '@salesforce/core';
import AuditTestContext from '../../mocks/auditTestContext.js';
import RuleRegistry from '../../../src/libs/audit-engine/registry/ruleRegistry.js';
import { AuditRunConfig, loadPolicy } from '../../../src/libs/audit-engine/index.js';
import ProfilesPolicy from '../../../src/libs/audit-engine/registry/policies/profiles.js';
import EnforcePermissionsOnProfileLike from '../../../src/libs/audit-engine/registry/rules/enforcePermissionsOnProfileLike.js';
import {
  PermissionRiskLevel,
  PolicyConfig,
  ProfileClassifications,
  UserPrivilegeLevel,
} from '../../../src/libs/audit-engine/registry/shape/schema.js';
import { PartialPolicyRuleResult } from '../../../src/libs/audit-engine/registry/context.types.js';
import { newRuleResult } from '../../mocks/testHelpers.js';
import { AuditPolicyResult } from '../../../src/libs/audit-engine/registry/result.types.js';
import { createDigest } from '../../../src/utils.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policies.general');
const ruleMessages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.enforceClassificationPresets');
const ipRangesMessages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.enforceLoginIpRanges');

async function runPolicy(con: Connection, config: AuditRunConfig): Promise<AuditPolicyResult> {
  const pol = loadPolicy('profiles', config);
  const policyResult = await pol.run({ targetOrgConnection: con });
  return policyResult;
}

describe('profile policy', () => {
  const $$ = new AuditTestContext();
  let defaultConfig: PolicyConfig;

  function stubUserClassificationRule(mockResult: PartialPolicyRuleResult) {
    return $$.context.SANDBOX.stub(EnforcePermissionsOnProfileLike.prototype, 'run').resolves(mockResult);
  }

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

  describe('policy loading', () => {
    it('uses custom registry to resolve rules when its passed to the constructor', async () => {
      // Arrange
      defaultConfig.rules = { TestRule: { enabled: true } };
      const reg = new TestProfilesRegistry();

      // Act
      const pol = new ProfilesPolicy(defaultConfig, $$.mockAuditConfig, reg);
      const policyResult = await pol.run({ targetOrgConnection: $$.targetOrgConnection });

      // Assert
      expect(Object.keys(policyResult.executedRules)).to.deep.equal(['TestRule']);
    });

    it('runs all rules in policy configuration with fully valid config', async () => {
      // Act
      const policyResult = await runPolicy($$.targetOrgConnection, $$.mockAuditConfig);

      // Assert
      expect(policyResult.isCompliant).to.equal(true);
      const executedRuleNames = Object.keys(policyResult.executedRules);
      expect(executedRuleNames).to.deep.equal(['EnforcePermissionClassifications']);
    });

    it('ignores configured rules that cannot be resolved by implementation', async () => {
      // Arrange
      defaultConfig.rules['UnknownRuleDoesNotExist'] = { enabled: true };

      // Act
      const policyResult = await runPolicy($$.targetOrgConnection, $$.mockAuditConfig);

      // Assert
      expect(policyResult.isCompliant).to.equal(true);
      const executedRuleNames = Object.keys(policyResult.executedRules);
      expect(executedRuleNames).to.deep.equal(['EnforcePermissionClassifications']);
    });
  });

  describe('entity resolve', () => {
    it('ignores profiles from config where metadata is not resolved from target org', async () => {
      // Arrange
      stubUserClassificationRule(newRuleResult('EnforcePermissionClassifications'));

      // Act
      const policyResult = await runPolicy($$.targetOrgConnection, $$.mockAuditConfig);

      // Assert
      expect(policyResult.ignoredEntities).to.deep.equal([
        { name: 'Custom Profile', message: messages.getMessage('profile-invalid-no-metadata') },
      ]);
      expect(policyResult.auditedEntities).to.deep.equal(['System Administrator', 'Standard User']);
    });

    it('ignores profile from config that does not exist on target org', async () => {
      // Arrange
      stubUserClassificationRule(newRuleResult('EnforcePermissionClassifications'));
      $$.mocks.mockProfiles('admin-and-standard-profiles');

      // Act
      const policyResult = await runPolicy($$.targetOrgConnection, $$.mockAuditConfig);

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
      stubUserClassificationRule(newRuleResult('EnforcePermissionClassifications'));
      $$.mockProfileClassification('Custom Profile', { role: UserPrivilegeLevel.UNKNOWN });

      // Act
      const policyResult = await runPolicy($$.targetOrgConnection, $$.mockAuditConfig);

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
      const policyResult = await runPolicy($$.targetOrgConnection, $$.mockAuditConfig);

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
        const policyResult = await runPolicy($$.targetOrgConnection, $$.mockAuditConfig);

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
        const result = await runPolicy($$.targetOrgConnection, $$.mockAuditConfig);

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
        const result = await runPolicy($$.targetOrgConnection, $$.mockAuditConfig);

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
        const result = await runPolicy($$.targetOrgConnection, $$.mockAuditConfig);

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
        const result = await runPolicy($$.targetOrgConnection, $$.mockAuditConfig);

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
        const result = await runPolicy($$.targetOrgConnection, $$.mockAuditConfig);

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
        const result = await runPolicy($$.targetOrgConnection, $$.mockAuditConfig);

        // Assert
        const ruleResult = result.executedRules.EnforceLoginIpRanges;
        assert.isDefined(ruleResult);
        expect(ruleResult.violations).to.deep.equal([]);
      });
    });
  });

  describe('result post-processing', () => {
    it('evaluates entities with no violations as compliant', async () => {
      // Arrange
      const mockResult = newRuleResult('EnforcePermissionClassifications');
      mockResult.violations.push(
        { identifier: ['Standard User', 'ViewSetup'], message: 'Irrelevant msg' },
        { identifier: ['Standard User', 'CustomizeApplication'], message: 'Irrelevant msg' }
      );
      stubUserClassificationRule(mockResult);

      // Act
      const policyResult = await runPolicy($$.targetOrgConnection, $$.mockAuditConfig);

      // Assert
      expect(policyResult.isCompliant).to.be.false;
      const ruleResult = policyResult.executedRules.EnforcePermissionClassifications;
      expect(ruleResult.compliantEntities).to.deep.equal(['System Administrator']);
      expect(ruleResult.violatedEntities).to.deep.equal(['Standard User']);
    });

    it('evaluates entities with warnings as compliant', async () => {
      // Arrange
      const mockResult = newRuleResult('EnforcePermissionClassifications');
      mockResult.warnings.push(
        { identifier: ['Standard User', 'ViewSetup'], message: 'Irrelevant msg' },
        { identifier: ['Standard User', 'ViewAllData'], message: 'Irrelevant msg' }
      );
      stubUserClassificationRule(mockResult);

      // Act
      const policyResult = await runPolicy($$.targetOrgConnection, $$.mockAuditConfig);

      // Assert
      expect(policyResult.isCompliant).to.be.true;
      const ruleResult = policyResult.executedRules.EnforcePermissionClassifications;
      expect(ruleResult.compliantEntities).to.deep.equal(['System Administrator', 'Standard User']);
      expect(ruleResult.violatedEntities).to.deep.equal([]);
    });
  });
});

class TestProfilesRegistry extends RuleRegistry {
  public constructor() {
    super({
      TestRule: EnforcePermissionsOnProfileLike,
    });
  }
}
