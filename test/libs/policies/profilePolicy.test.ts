import { expect } from 'chai';
import AuditTestContext from '../../mocks/auditTestContext.js';
import ProfilePolicy from '../../../src/libs/policies/profilePolicy.js';
import { PermissionRiskLevelPresets } from '../../../src/libs/policies/types.js';
import AuditRunConfig from '../../../src/libs/policies/interfaces/auditRunConfig.js';

const MOCK_AUDIT_CONTEXT = new AuditRunConfig();

const DEFAULT_PROFILE_CONFIG = {
  enabled: true,
  profiles: {
    'Test Profile 1': {
      preset: PermissionRiskLevelPresets.ADMIN,
    },
    'Test Profile 2': {
      preset: PermissionRiskLevelPresets.STANDARD_USER,
    },
  },
  rules: {
    EnforceClassificationPresets: {
      enabled: true,
    },
  },
};

describe('profile policy', () => {
  const $$ = new AuditTestContext();

  beforeEach(async () => {
    await $$.init();
  });

  afterEach(async () => {
    $$.reset();
  });

  it('runs all rules in policy configuration with fully valid config', async () => {
    // Arrange
    const pol = new ProfilePolicy(DEFAULT_PROFILE_CONFIG, MOCK_AUDIT_CONTEXT);

    // Act
    const policyResult = await pol.run({ targetOrgConnection: await $$.targetOrg.getConnection() });

    // Assert
    expect(policyResult.isCompliant).to.equal(true);
    const executedRuleNames = Object.keys(policyResult.executedRules);
    expect(executedRuleNames).to.deep.equal(['EnforceClassificationPresets']);
  });
});
