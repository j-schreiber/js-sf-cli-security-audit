import { expect, assert } from 'chai';
import AcceptedRisks from '../../src/libs/audit-engine/accepted-risks/acceptedRisks.js';
import { PartialPolicyRuleResult } from '../../src/libs/audit-engine/registry/context.types.js';

describe('accepted risks', () => {
  const riskManager = new AcceptedRisks({
    users: {
      MyTestRule: {
        identifier1: {
          identifier2: {
            reason: 'Is safe to use',
          },
          '*': {
            reason: 'Matches all other',
          },
        },
      },
      TestProfileBasedRule: {
        'username@example.com': {
          '*': {
            reason: 'Clears all for this user',
          },
        },
      },
    },
  });

  it('matches accepted risk with exact identifier match', () => {
    // Act
    const myTestIdentifier = ['identifier1', 'identifier2'];
    const risk = riskManager.matchRisk('users', 'MyTestRule', ...myTestIdentifier);

    // Assert
    assert.isDefined(risk);
    expect(risk).to.deep.equal({ reason: 'Is safe to use' });
  });

  it('matches accepted risk with wildcard identifier match', () => {
    // Act
    const myTestIdentifier = ['identifier1', 'not-explicitly-matched'];
    const risk = riskManager.matchRisk('users', 'MyTestRule', ...myTestIdentifier);

    // Assert
    assert.isDefined(risk);
    expect(risk).to.deep.equal({ reason: 'Matches all other' });
  });

  it('does not match excessive identifiers that are not configured', () => {
    // Act
    const myTestIdentifier = ['identifier1', 'wild-card-matching', 'another'];
    const risk = riskManager.matchRisk('users', 'MyTestRule', ...myTestIdentifier);

    // Assert
    assert.isUndefined(risk);
  });

  it('scrubs matching violation from partial rule result', () => {
    // Act
    const testViolation1 = { identifier: ['identifier1', 'will-be-matched'], message: 'Testing 1' };
    const testViolation2 = { identifier: ['identifier2', 'not-explicitly-matched'], message: 'Testing 2' };
    const partialResult: PartialPolicyRuleResult = {
      ruleName: 'MyTestRule',
      violations: [testViolation1, testViolation2],
      mutedViolations: [],
      errors: [],
      warnings: [],
    };
    const scrubbedResult = riskManager.scrub('users', partialResult);

    // Assert
    expect(scrubbedResult.violations).to.deep.equal([testViolation2]);
    expect(scrubbedResult.mutedViolations).to.deep.equal([{ ...testViolation1, reason: 'Matches all other' }]);
  });
});
