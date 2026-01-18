import { expect, assert } from 'chai';
import { Messages } from '@salesforce/core';
import AuditTestContext, { newRuleResult } from '../../mocks/auditTestContext.js';
import { ProfilesRegistry } from '../../../src/libs/core/registries/profiles.js';
import ProfilePolicy from '../../../src/libs/core/policies/profilePolicy.js';
import RuleRegistry from '../../../src/libs/core/registries/ruleRegistry.js';
import { BasePolicyFileContent } from '../../../src/libs/core/file-mgmt/schema.js';
import { PartialPolicyRuleResult } from '../../../src/libs/core/registries/types.js';
import { UserPrivilegeLevel } from '../../../src/libs/core/policy-types.js';
import { PermissionRiskLevel } from '../../../src/libs/core/classification-types.js';
import EnforcePermissionsOnProfileLike from '../../../src/libs/core/registries/rules/enforcePermissionsOnProfileLike.js';
import { parseProfileFromFile } from '../../mocks/testHelpers.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policies.general');
const ruleMessages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.enforceClassificationPresets');

const DEFAULT_PROFILE_CONFIG: BasePolicyFileContent = {
  enabled: true,
  rules: {
    EnforcePermissionClassifications: {
      enabled: true,
    },
  },
};

const EXPECTED_RESOLVED_DEFAULT_ENTITIES = {
  'System Administrator': {
    role: 'Admin',
    name: 'System Administrator',
    metadata: parseProfileFromFile('admin-profile-with-metadata'),
  },
  'Standard User': {
    role: 'Standard User',
    name: 'Standard User',
    metadata: parseProfileFromFile('standard-profile-with-metadata'),
  },
};

describe('profile policy', () => {
  const $$ = new AuditTestContext();

  function stubUserClassificationRule(mockResult: PartialPolicyRuleResult) {
    return $$.context.SANDBOX.stub(EnforcePermissionsOnProfileLike.prototype, 'run').resolves(mockResult);
  }

  beforeEach(async () => {
    $$.mockAuditConfig.classifications = {
      profiles: {
        content: {
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
      },
    };
    await $$.init();
  });

  afterEach(async () => {
    $$.reset();
  });

  describe('policy loading', () => {
    it('initialises all registered rules from policy registry', async () => {
      // Act
      const resolveResult = ProfilesRegistry.resolveRules(DEFAULT_PROFILE_CONFIG.rules, $$.mockAuditConfig);

      // Assert
      expect(resolveResult.enabledRules.length).to.equal(1);
      expect(resolveResult.skippedRules).to.deep.equal([]);
      expect(resolveResult.resolveErrors).to.deep.equal([]);
      const ruleResult = await resolveResult.enabledRules[0].run({
        targetOrgConnection: $$.targetOrgConnection,
        resolvedEntities: EXPECTED_RESOLVED_DEFAULT_ENTITIES,
      });
      expect(ruleResult.isCompliant).to.be.undefined;
      expect(ruleResult.violatedEntities).to.be.undefined;
      expect(ruleResult.compliantEntities).to.be.undefined;
    });

    it('uses custom registry to resolve rules when its passed to the constructor', async () => {
      // Arrange
      const CONFIG = structuredClone(DEFAULT_PROFILE_CONFIG);
      CONFIG.rules = { TestRule: { enabled: true } };
      const reg = new TestProfilesRegistry();

      // Act
      const pol = new ProfilePolicy(CONFIG, $$.mockAuditConfig, reg);
      const policyResult = await pol.run({ targetOrgConnection: $$.targetOrgConnection });

      // Assert
      expect(Object.keys(policyResult.executedRules)).to.deep.equal(['TestRule']);
    });

    it('runs all rules in policy configuration with fully valid config', async () => {
      // Act
      const pol = new ProfilePolicy(DEFAULT_PROFILE_CONFIG, $$.mockAuditConfig);
      const policyResult = await pol.run({ targetOrgConnection: $$.targetOrgConnection });

      // Assert
      expect(policyResult.isCompliant).to.equal(true);
      const executedRuleNames = Object.keys(policyResult.executedRules);
      expect(executedRuleNames).to.deep.equal(['EnforcePermissionClassifications']);
    });

    it('ignores configured rules that cannot be resolved by implementation', async () => {
      // Arrange
      const CONFIG = structuredClone(DEFAULT_PROFILE_CONFIG);
      CONFIG.rules['UnknownRuleDoesNotExist'] = { enabled: true };

      // Act
      const pol = new ProfilePolicy(CONFIG, $$.mockAuditConfig);
      const policyResult = await pol.run({ targetOrgConnection: $$.targetOrgConnection });

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
      const pol = new ProfilePolicy(DEFAULT_PROFILE_CONFIG, $$.mockAuditConfig);
      const policyResult = await pol.run({ targetOrgConnection: $$.targetOrgConnection });

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
      const pol = new ProfilePolicy(DEFAULT_PROFILE_CONFIG, $$.mockAuditConfig);
      const policyResult = await pol.run({ targetOrgConnection: $$.targetOrgConnection });

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
      const pol = new ProfilePolicy(DEFAULT_PROFILE_CONFIG, $$.mockAuditConfig);
      const policyResult = await pol.run({ targetOrgConnection: $$.targetOrgConnection });

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
      const pol = new ProfilePolicy(DEFAULT_PROFILE_CONFIG, $$.mockAuditConfig);
      const policyResult = await pol.run({ targetOrgConnection: $$.targetOrgConnection });

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
        const CONFIG = structuredClone(DEFAULT_PROFILE_CONFIG);
        CONFIG.rules = { EnforcePermissionClassifications: { enabled: true } };
        $$.mockAuditConfig.classifications.customPermissions = {
          content: {
            permissions: {
              CriticalCustomPermission: { classification: PermissionRiskLevel.CRITICAL },
            },
          },
        };

        // Act
        const pol = new ProfilePolicy(CONFIG, $$.mockAuditConfig);
        const policyResult = await pol.run({ targetOrgConnection: $$.targetOrgConnection });

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
      const pol = new ProfilePolicy(DEFAULT_PROFILE_CONFIG, $$.mockAuditConfig);
      const policyResult = await pol.run({ targetOrgConnection: $$.targetOrgConnection });

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
      const pol = new ProfilePolicy(DEFAULT_PROFILE_CONFIG, $$.mockAuditConfig);
      const policyResult = await pol.run({ targetOrgConnection: $$.targetOrgConnection });

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
