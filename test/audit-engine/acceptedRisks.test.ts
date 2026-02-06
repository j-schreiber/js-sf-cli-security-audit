import { expect } from 'chai';
import { Messages } from '@salesforce/core';
import { PartialPolicyRuleResult } from '../../src/libs/audit-engine/registry/context.types.js';
import { PolicyRuleViolation } from '../../src/libs/audit-engine/registry/result.types.js';
import { RiskTree, TreeNode } from '../../src/libs/audit-engine/accepted-risks/acceptedRisks.types.js';
import AcceptedRisks from '../../src/libs/audit-engine/accepted-risks/acceptedRisks.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'acceptedRisks');

describe('accepted risks', () => {
  let defaultRisks: RiskTree;

  beforeEach(() => {
    defaultRisks = {
      users: {
        MyTestRule: {
          key1: {
            subIdentifier2: {
              reason: 'Is safe to use',
            },
            '*': {
              reason: 'Matches all other',
            },
          },
          key3: {
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
    };
  });

  it('merges default built-in risks with custom risks', () => {
    // Act
    const riskManager = new AcceptedRisks({
      users: {
        NoStandardProfilesOnActiveUsers: {
          'my-test-user@example.com': { 'Minimum Access': { reason: 'This is okay' } },
        },
      },
    });

    const violation = {
      identifier: ['some-username@example.com', 'Sales Insights Integration User'],
      message: 'Testing',
    };
    const partialResult = initRuleResult('NoStandardProfilesOnActiveUsers', [violation]);
    const scrubbedResult = riskManager.scrub('users', partialResult);

    // Assert
    expect(scrubbedResult.violations).to.deep.equal([]);
    expect(scrubbedResult.mutedViolations).to.deep.equal([
      { ...violation, reason: messages.getMessage('user-skipped-cannot-manage') },
    ]);
  });

  it('matches accepted risk with exact identifier match', () => {
    // Act
    const riskManager = new AcceptedRisks(defaultRisks);
    const violation = { identifier: ['key1', 'subIdentifier2'], message: 'Testing' };
    const partialResult = initRuleResult('MyTestRule', [violation]);
    const scrubbedResult = riskManager.scrub('users', partialResult);

    // Assert
    expect(scrubbedResult.violations).to.deep.equal([]);
    expect(scrubbedResult.mutedViolations).to.deep.equal([{ ...violation, reason: 'Is safe to use' }]);
  });

  it('matches accepted risk with wildcard identifier match', () => {
    // Act
    const riskManager = new AcceptedRisks(defaultRisks);
    const violation = { identifier: ['key1', 'not-explicitly-matched'], message: 'Testing' };
    const partialResult = initRuleResult('MyTestRule', [violation]);
    const scrubbedResult = riskManager.scrub('users', partialResult);

    // Assert
    expect(scrubbedResult.violations).to.deep.equal([]);
    expect(scrubbedResult.mutedViolations).to.deep.equal([{ ...violation, reason: 'Matches all other' }]);
  });

  it('does not match excessive identifiers that are not configured', () => {
    // Act
    // Act
    const riskManager = new AcceptedRisks(defaultRisks);
    const violation = { identifier: ['key1', 'subIdentifier2', 'more-specific'], message: 'Testing' };
    const partialResult = initRuleResult('MyTestRule', [violation]);
    const scrubbedResult = riskManager.scrub('users', partialResult);

    // Assert
    expect(scrubbedResult.violations).to.deep.equal([violation]);
    expect(scrubbedResult.mutedViolations).to.deep.equal([]);
  });

  it('scrubs matching violation from partial rule result', () => {
    // Act
    const riskManager = new AcceptedRisks(defaultRisks);
    const testViolation1 = { identifier: ['key1', 'will-be-matched'], message: 'Testing 1' };
    const testViolation2 = { identifier: ['key2', 'not-explicitly-matched'], message: 'Testing 2' };
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

  it('does not match accepted risks without rule name', () => {
    // Arrange
    defaultRisks.profiles = { key1: { reason: 'Should not match' } };
    const riskManager = new AcceptedRisks(defaultRisks);

    // Act
    const partialResult = initRuleResult('MyTestRule', [{ identifier: ['key1'], message: 'My message' }]);
    const scrubbedResult = riskManager.scrub('profiles', partialResult);

    // Assert
    expect(scrubbedResult.violations).to.have.lengthOf(1);
    expect(scrubbedResult.mutedViolations).to.deep.equal([]);
  });

  it('matches multiple violations with wildcard from sub-identifier', () => {
    // Act
    const riskManager = new AcceptedRisks(defaultRisks);
    const partialResult = initRuleResult('MyTestRule', [
      { identifier: ['key1', 'subIdentifier3'], message: 'Msg 1' },
      { identifier: ['key1', 'subIdentifier4'], message: 'Msg 2' },
      { identifier: ['key1', 'subIdentifier5'], message: 'Msg 3' },
      { identifier: ['key1', 'subIdentifier6'], message: 'Msg 4' },
    ]);
    const scrubbedResult = riskManager.scrub('users', partialResult);

    // Assert
    expect(scrubbedResult.violations).to.deep.equal([]);
    expect(scrubbedResult.mutedViolations).to.have.lengthOf(4);
  });

  it('shows decent performance when scrubbing 1000s of violations with accepted risks', () => {
    // Arrange
    const violations: PolicyRuleViolation[] = [];
    for (let i = 0; i < 5; i++) {
      for (let j = 0; j < 1000; j++) {
        violations.push({ identifier: [`key${i}`, `subIdentifier${j}`], message: 'Testing' });
      }
    }
    const ruleRisks = defaultRisks.users!['MyTestRule'];
    const risks: TreeNode = {};
    for (let k = 0; k < 1000; k++) {
      risks[`subIdentifier${k}`] = { reason: 'Testing' };
    }
    defaultRisks.users!['MyTestRule'] = { ...ruleRisks, ...{ key4: risks } };
    const riskManager = new AcceptedRisks(defaultRisks);

    // Act
    const partialResult = initRuleResult('MyTestRule', violations);
    const scrubbedResult = riskManager.scrub('users', partialResult);

    // Assert
    // default matchers catch all "key1" and "identifier3" via wildcard
    // the custom matchers from arrange catch all "identifier4"
    for (const violation of scrubbedResult.violations) {
      expect(violation.identifier[0]).not.to.equal('key1');
      expect(violation.identifier[0]).not.to.equal('key3');
      expect(violation.identifier[0]).not.to.equal('key4');
    }
    expect(scrubbedResult.violations).to.have.lengthOf(2000);
    expect(scrubbedResult.mutedViolations).to.have.lengthOf(3000);
  });

  it('returns all risks as flat list', () => {
    // Act
    const riskManager = new AcceptedRisks(defaultRisks);
    const risks = riskManager.getStats();

    // Assert
    expect(risks).to.have.lengthOf(5);
    expect(risks[0]).to.deep.equal({
      rule: 'NoStandardProfilesOnActiveUsers',
      policy: 'users',
      matcher: ['*', 'Sales Insights Integration User'],
      appliedCount: 0,
      type: 'standard',
    });
    expect(risks[1]).to.deep.equal({
      rule: 'MyTestRule',
      policy: 'users',
      matcher: ['key1', 'subIdentifier2'],
      appliedCount: 0,
      type: 'custom',
    });
    expect(risks[2]).to.deep.equal({
      rule: 'MyTestRule',
      policy: 'users',
      matcher: ['key1', '*'],
      appliedCount: 0,
      type: 'custom',
    });
    expect(risks[3]).to.deep.equal({
      rule: 'MyTestRule',
      policy: 'users',
      matcher: ['key3', '*'],
      appliedCount: 0,
      type: 'custom',
    });
    expect(risks[4]).to.deep.equal({
      rule: 'TestProfileBasedRule',
      policy: 'users',
      matcher: ['username@example.com', '*'],
      appliedCount: 0,
      type: 'custom',
    });
  });

  it('accurately counts usage for an accepted risk after scrubbing violations', () => {
    // Act
    const riskManager = new AcceptedRisks(defaultRisks);
    const partialResult = initRuleResult('MyTestRule', [
      { identifier: ['key1', 'subIdentifier3'], message: 'Msg 1' },
      { identifier: ['key1', 'subIdentifier4'], message: 'Msg 2' },
      { identifier: ['key1', 'subIdentifier5'], message: 'Msg 3' },
      { identifier: ['key1', 'subIdentifier6'], message: 'Msg 4' },
    ]);
    riskManager.scrub('users', partialResult);
    const stats = riskManager.getStats();

    // Assert
    const matchedRisk = stats[2];
    expect(matchedRisk).to.deep.equal({
      rule: 'MyTestRule',
      policy: 'users',
      matcher: ['key1', '*'],
      appliedCount: 4,
      type: 'custom',
    });
  });
});

function initRuleResult(ruleName: string, violations: PolicyRuleViolation[]): PartialPolicyRuleResult {
  return {
    ruleName,
    violations,
    mutedViolations: [],
    errors: [],
    warnings: [],
  };
}
