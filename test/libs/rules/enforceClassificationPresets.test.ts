import { expect } from 'chai';
import AuditTestContext from '../../mocks/auditTestContext.js';
import EnforceClassificationPresets from '../../../src/libs/policies/rules/enforceClassificationPresets.js';
import PolicySet from '../../../src/libs/policies/policySet.js';

describe('enforce classification presets', () => {
  const $$ = new AuditTestContext();

  beforeEach(async () => {
    $$.init();
  });

  afterEach(async () => {
    $$.reset();
  });

  it('runs rule with fully valid context', async () => {
    // Arrange
    const rule = new EnforceClassificationPresets({ enabled: true });
    const auditConfig = new PolicySet();
    // Act
    const result = await rule.run({
      targetOrgConnection: await $$.targetOrg.getConnection(),
      auditConfig,
    });

    // Assert
    expect(result.ruleName).to.equal('EnforceClassificationPresets');
    expect(result.isCompliant).to.equal(true);
  });
});
