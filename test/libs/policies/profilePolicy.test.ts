import { expect } from 'chai';
import AuditTestContext from '../../mocks/auditTestContext.js';
import ProfilePolicy from '../../../src/libs/policies/profilePolicy.js';
import { PermissionRiskLevelPresets } from '../../../src/libs/policies/types.js';
import PolicySet from '../../../src/libs/policies/policySet.js';

describe('profile policy', () => {
  const $$ = new AuditTestContext();

  beforeEach(async () => {
    $$.init();
  });

  afterEach(async () => {
    $$.reset();
  });

  it('runs all rules in policy configuration with fully valid config', async () => {
    // Arrange
    const pol = new ProfilePolicy({
      enabled: true,
      profiles: {
        'System Administrator': { preset: PermissionRiskLevelPresets.ADMIN },
        // 'Standard User': { preset: 'Standard' },
        // 'Custom System Administrator': { preset: 'Admin' },
      },
      rules: { EnforceClassificationPresets: { enabled: true } },
    });
    const auditConfig = new PolicySet();

    // Act
    const policyResult = await pol.run({ targetOrgConnection: await $$.targetOrg.getConnection(), auditConfig });

    // Assert
    expect(policyResult.isCompliant).to.equal(true);
    const executedRuleNames = Object.keys(policyResult.executedRules);
    expect(executedRuleNames).to.deep.equal(['EnforceClassificationPresets']);
  });
});
