import fs from 'node:fs';
import path from 'node:path';
import { expect } from 'chai';
import { Messages } from '@salesforce/core';
import { Profile as ProfileMetadata } from '@jsforce/jsforce-node/lib/api/metadata.js';
import AuditTestContext from '../../mocks/auditTestContext.js';
import ProfilePolicy from '../../../src/libs/policies/profilePolicy.js';
import { PermissionRiskLevelPresets } from '../../../src/libs/policies/types.js';
import AuditRunConfig from '../../../src/libs/policies/interfaces/auditRunConfig.js';
import { PolicyRuleExecutionResult, PolicyRuleViolation, RuleComponentMessage } from '../../../src/libs/audit/types.js';
import { Profile } from '../../../src/libs/policies/salesforceStandardTypes.js';
import { ProfilesPolicyFileContent } from '../../../src/libs/policies/schema.js';
import EnforceUserPermsClassificationOnProfiles from '../../../src/libs/policies/rules/enforceUserPermsClassificationOnProfiles.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policies.general');

const MOCK_AUDIT_CONTEXT = new AuditRunConfig();
const QUERY_RESULTS_DIR = path.join('test', 'mocks', 'data', 'queryResults');

const DEFAULT_PROFILE_CONFIG = {
  enabled: true,
  profiles: {
    'System Administrator': {
      preset: PermissionRiskLevelPresets.ADMIN,
    },
    'Standard User': {
      preset: PermissionRiskLevelPresets.STANDARD_USER,
    },
  },
  rules: {
    EnforceUserPermissionClassifications: {
      enabled: true,
    },
  },
} as ProfilesPolicyFileContent;

const MOCK_RULE_RESULT = {
  ruleName: 'EnforceUserPermissionClassifications',
  isCompliant: true,
  violations: new Array<PolicyRuleViolation>(),
  mutedViolations: [],
  warnings: new Array<RuleComponentMessage>(),
  errors: [],
} as PolicyRuleExecutionResult;

describe('profile policy', () => {
  const $$ = new AuditTestContext();

  function stubUserClassificationRule(mockResult: PolicyRuleExecutionResult) {
    return $$.context.SANDBOX.stub(EnforceUserPermsClassificationOnProfiles.prototype, 'run').resolves(mockResult);
  }

  beforeEach(async () => {
    await $$.init();
  });

  afterEach(async () => {
    $$.reset();
  });

  it('runs all rules in policy configuration with fully valid config', async () => {
    // Act
    const pol = new ProfilePolicy(DEFAULT_PROFILE_CONFIG, MOCK_AUDIT_CONTEXT);
    const policyResult = await pol.run({ targetOrgConnection: await $$.targetOrg.getConnection() });

    // Assert
    expect(policyResult.isCompliant).to.equal(true);
    const executedRuleNames = Object.keys(policyResult.executedRules);
    expect(executedRuleNames).to.deep.equal(['EnforceUserPermissionClassifications']);
  });

  it('ignores configured rules that cannot be resolved by implementation', async () => {
    // Arrange
    const CONFIG = structuredClone(DEFAULT_PROFILE_CONFIG);
    CONFIG.rules['UnknownRuleDoesNotExist'] = { enabled: true };

    // Act
    const pol = new ProfilePolicy(CONFIG, MOCK_AUDIT_CONTEXT);
    const policyResult = await pol.run({ targetOrgConnection: await $$.targetOrg.getConnection() });

    // Assert
    expect(policyResult.isCompliant).to.equal(true);
    const executedRuleNames = Object.keys(policyResult.executedRules);
    expect(executedRuleNames).to.deep.equal(['EnforceUserPermissionClassifications']);
  });

  it('resolves profiles from config to actual profile metadata from org', async () => {
    // Arrange
    const ruleSpy = stubUserClassificationRule(MOCK_RULE_RESULT);

    // Act
    const pol = new ProfilePolicy(DEFAULT_PROFILE_CONFIG, MOCK_AUDIT_CONTEXT);
    const policyResult = await pol.run({ targetOrgConnection: await $$.targetOrg.getConnection() });

    // Assert
    const adminProfile = loadProfileMetadata('admin-profile-with-metadata.json');
    const standardProfile = loadProfileMetadata('standard-profile-with-metadata.json');
    const expectedResolvedEntities = {
      'System Administrator': {
        preset: 'Admin',
        name: 'System Administrator',
        metadata: adminProfile,
      },
      'Standard User': {
        preset: 'Standard User',
        name: 'Standard User',
        metadata: standardProfile,
      },
    };
    expect(ruleSpy.callCount).to.equal(1);
    expect(ruleSpy.args.flat()[0]).to.deep.contain({
      resolvedEntities: expectedResolvedEntities,
    });
    expect(policyResult.auditedEntities).to.deep.equal(Object.keys(expectedResolvedEntities));
    expect(policyResult.ignoredEntities.length).to.equal(0);
  });

  it('ignores profiles from config that cannot be resolved from target org', async () => {
    // Arrange
    stubUserClassificationRule(MOCK_RULE_RESULT);
    $$.mocks.setQueryMock(
      "SELECT Name,Metadata FROM Profile WHERE Name = 'Custom Profile'",
      path.join(QUERY_RESULTS_DIR, 'empty.json')
    );
    const PROFILE_CONFIG = structuredClone(DEFAULT_PROFILE_CONFIG);
    PROFILE_CONFIG.profiles['Custom Profile'] = { preset: PermissionRiskLevelPresets.POWER_USER };

    // Act
    const pol = new ProfilePolicy(PROFILE_CONFIG, MOCK_AUDIT_CONTEXT);
    const policyResult = await pol.run({ targetOrgConnection: await $$.targetOrg.getConnection() });

    // Assert
    expect(policyResult.ignoredEntities).to.deep.equal([
      { name: 'Custom Profile', message: messages.getMessage('entity-not-found') },
    ]);
    expect(policyResult.auditedEntities).to.deep.equal(['System Administrator', 'Standard User']);
  });

  it('ignores profiles with UNKNOWN preset without attempting to resolve', async () => {
    // Arrange
    stubUserClassificationRule(MOCK_RULE_RESULT);
    const PROFILE_CONFIG = structuredClone(DEFAULT_PROFILE_CONFIG);
    PROFILE_CONFIG.profiles['Custom Profile'] = { preset: PermissionRiskLevelPresets.UNKNOWN };

    // Act
    const pol = new ProfilePolicy(PROFILE_CONFIG, MOCK_AUDIT_CONTEXT);
    const policyResult = await pol.run({ targetOrgConnection: await $$.targetOrg.getConnection() });

    // Assert
    expect(policyResult.ignoredEntities).to.deep.equal([
      { name: 'Custom Profile', message: messages.getMessage('preset-unknown', ['Profile']) },
    ]);
    expect(policyResult.auditedEntities).to.deep.equal(['System Administrator', 'Standard User']);
  });
});

function loadProfileMetadata(profileFileName: string): ProfileMetadata {
  const content = fs.readFileSync(path.join(QUERY_RESULTS_DIR, profileFileName), 'utf-8');
  const records = JSON.parse(content) as Profile[];
  return records[0].Metadata;
}
