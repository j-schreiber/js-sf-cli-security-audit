import { expect } from 'chai';
import AuditTestContext from '../../mocks/auditTestContext.js';
import RuleRegistry from '../../../src/libs/audit-engine/registry/ruleRegistry.js';
import ProfilesPolicy from '../../../src/libs/audit-engine/registry/policies/profiles.js';
import EnforcePermissionsOnProfileLike from '../../../src/libs/audit-engine/registry/rules/enforcePermissionsOnProfileLike.js';
import { PolicyConfig, UserPrivilegeLevel } from '../../../src/libs/audit-engine/registry/shape/schema.js';
import { PartialPolicyRuleResult } from '../../../src/libs/audit-engine/registry/context.types.js';
import { newRuleResult, resolveAndRun } from '../../mocks/testHelpers.js';

describe('policy - base implementation', () => {
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
      const policyResult = await pol.executeRules({ targetOrgConnection: $$.targetOrgConnection });

      // Assert
      expect(Object.keys(policyResult)).to.deep.equal(['TestRule']);
    });

    it('runs all rules in policy configuration with fully valid config', async () => {
      // Act
      const policyResult = await resolveAndRun('profiles', $$);

      // Assert
      expect(policyResult.isCompliant).to.equal(true);
      const executedRuleNames = Object.keys(policyResult.executedRules);
      expect(executedRuleNames).to.deep.equal(['EnforcePermissionClassifications']);
    });

    it('ignores configured rules that cannot be resolved by implementation', async () => {
      // Arrange
      defaultConfig.rules['UnknownRuleDoesNotExist'] = { enabled: true };

      // Act
      const policyResult = await resolveAndRun('profiles', $$);

      // Assert
      expect(policyResult.isCompliant).to.equal(true);
      const executedRuleNames = Object.keys(policyResult.executedRules);
      expect(executedRuleNames).to.deep.equal(['EnforcePermissionClassifications']);
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
      const policyResult = await resolveAndRun('profiles', $$);

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
      const policyResult = await resolveAndRun('profiles', $$);

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
