import fs from 'node:fs';
import path from 'node:path';
import { expect, assert } from 'chai';
import { Messages } from '@salesforce/core';
import { Profile as ProfileMetadata } from '@jsforce/jsforce-node/lib/api/metadata.js';
import AuditTestContext, { newRuleResult } from '../../mocks/auditTestContext.js';
import ProfilePolicyRegistry from '../../../src/libs/core/registries/profiles.js';
import ProfilePolicy from '../../../src/libs/policies/profilePolicy.js';
import { Profile } from '../../../src/libs/policies/salesforceStandardTypes.js';
import RuleRegistry from '../../../src/libs/core/registries/ruleRegistry.js';
import { AuditRunConfig, ProfilesPolicyFileContent } from '../../../src/libs/core/file-mgmt/schema.js';
import { PartialPolicyRuleResult } from '../../../src/libs/core/registries/types.js';
import EnforceUserPermsClassificationOnProfiles from '../../../src/libs/core/registries/rules/enforceUserPermsClassificationOnProfiles.js';
import { ProfilesRiskPreset } from '../../../src/libs/core/policy-types.js';
import { PermissionRiskLevel } from '../../../src/libs/core/classification-types.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policies.general');

const QUERY_RESULTS_DIR = path.join('test', 'mocks', 'data', 'queryResults');

const DEFAULT_PROFILE_CONFIG: ProfilesPolicyFileContent = {
  enabled: true,
  profiles: {
    'System Administrator': {
      preset: ProfilesRiskPreset.ADMIN,
    },
    'Standard User': {
      preset: ProfilesRiskPreset.STANDARD_USER,
    },
    'Custom Profile': {
      preset: ProfilesRiskPreset.POWER_USER,
    },
  },
  rules: {
    EnforceUserPermissionClassifications: {
      enabled: true,
    },
  },
};

const EXPECTED_RESOLVED_DEFAULT_ENTITIES = {
  'System Administrator': {
    preset: 'Admin',
    name: 'System Administrator',
    metadata: loadProfileMetadata('admin-profile-with-metadata.json'),
  },
  'Standard User': {
    preset: 'Standard User',
    name: 'Standard User',
    metadata: loadProfileMetadata('standard-profile-with-metadata.json'),
  },
};

describe('profile policy', () => {
  const $$ = new AuditTestContext();

  function stubUserClassificationRule(mockResult: PartialPolicyRuleResult) {
    return $$.context.SANDBOX.stub(EnforceUserPermsClassificationOnProfiles.prototype, 'run').resolves(mockResult);
  }

  beforeEach(async () => {
    await $$.init();
  });

  afterEach(async () => {
    $$.reset();
  });

  it('initialises all registered rules from policy registry', async () => {
    // Act
    const reg = new ProfilePolicyRegistry();
    const resolveResult = reg.resolveRules(DEFAULT_PROFILE_CONFIG.rules, $$.mockAuditConfig);

    // Assert
    expect(resolveResult.enabledRules.length).to.equal(1);
    expect(resolveResult.skippedRules).to.deep.equal([]);
    expect(resolveResult.resolveErrors).to.deep.equal([]);
    const ruleResult = await resolveResult.enabledRules[0].run({
      targetOrgConnection: await $$.targetOrg.getConnection(),
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
    const policyResult = await pol.run({ targetOrgConnection: await $$.targetOrg.getConnection() });

    // Assert
    expect(Object.keys(policyResult.executedRules)).to.deep.equal(['TestRule']);
  });

  it('runs all rules in policy configuration with fully valid config', async () => {
    // Act
    const pol = new ProfilePolicy(DEFAULT_PROFILE_CONFIG, $$.mockAuditConfig);
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
    const pol = new ProfilePolicy(CONFIG, $$.mockAuditConfig);
    const policyResult = await pol.run({ targetOrgConnection: await $$.targetOrg.getConnection() });

    // Assert
    expect(policyResult.isCompliant).to.equal(true);
    const executedRuleNames = Object.keys(policyResult.executedRules);
    expect(executedRuleNames).to.deep.equal(['EnforceUserPermissionClassifications']);
  });

  it('returns compliant for custom permissions rule when context has no custom permissions', async () => {
    // Arrange
    const CONFIG = structuredClone(DEFAULT_PROFILE_CONFIG);
    CONFIG.rules = { EnforceCustomPermissionClassifications: { enabled: true } };

    // Act
    const pol = new ProfilePolicy(CONFIG, $$.mockAuditConfig);
    const policyResult = await pol.run({ targetOrgConnection: await $$.targetOrg.getConnection() });

    // Assert
    expect(policyResult.isCompliant).to.equal(true);
    const executedRuleNames = Object.keys(policyResult.executedRules);
    expect(executedRuleNames).to.deep.equal(['EnforceCustomPermissionClassifications']);
    assert.isDefined(policyResult.executedRules.EnforceCustomPermissionClassifications);
    expect(policyResult.executedRules.EnforceCustomPermissionClassifications.isCompliant).to.be.true;
  });

  it('reports error in custom perms rule if permission classification does not match preset', async () => {
    // Arrange
    const CONFIG = structuredClone(DEFAULT_PROFILE_CONFIG);
    CONFIG.rules = { EnforceCustomPermissionClassifications: { enabled: true } };
    const auditConfig: AuditRunConfig = {
      policies: {},
      classifications: {
        customPermissions: {
          content: {
            permissions: {
              CriticalCustomPermission: { classification: PermissionRiskLevel.CRITICAL },
            },
          },
        },
      },
    };

    // Act
    const pol = new ProfilePolicy(CONFIG, auditConfig);
    const policyResult = await pol.run({ targetOrgConnection: await $$.targetOrg.getConnection() });

    // Assert
    expect(policyResult.isCompliant).to.equal(false);
    const executedRuleNames = Object.keys(policyResult.executedRules);
    expect(executedRuleNames).to.deep.equal(['EnforceCustomPermissionClassifications']);
    assert.isDefined(policyResult.executedRules.EnforceCustomPermissionClassifications);
    expect(policyResult.executedRules.EnforceCustomPermissionClassifications.isCompliant).to.be.false;
    expect(policyResult.executedRules.EnforceCustomPermissionClassifications.violations).to.deep.equal([
      {
        identifier: ['Standard User', 'CriticalCustomPermission'],
        message: 'Permission is classified as "Critical" and not allowed in preset "Standard User".',
      },
    ]);
  });

  it('ignores profiles from config that cannot be resolved from target org', async () => {
    // Arrange
    stubUserClassificationRule(newRuleResult('EnforceUserPermissionClassifications'));
    $$.mocks.setQueryMock(
      "SELECT Name,Metadata FROM Profile WHERE Name = 'Custom Profile'",
      path.join(QUERY_RESULTS_DIR, 'empty.json')
    );
    const PROFILE_CONFIG = structuredClone(DEFAULT_PROFILE_CONFIG);
    PROFILE_CONFIG.profiles['Custom Profile'] = { preset: ProfilesRiskPreset.POWER_USER };

    // Act
    const pol = new ProfilePolicy(PROFILE_CONFIG, $$.mockAuditConfig);
    const policyResult = await pol.run({ targetOrgConnection: await $$.targetOrg.getConnection() });

    // Assert
    expect(policyResult.ignoredEntities).to.deep.equal([
      { name: 'Custom Profile', message: messages.getMessage('entity-not-found') },
    ]);
    expect(policyResult.auditedEntities).to.deep.equal(['System Administrator', 'Standard User']);
  });

  it('ignores profiles with UNKNOWN preset without attempting to resolve', async () => {
    // Arrange
    stubUserClassificationRule(newRuleResult('EnforceUserPermissionClassifications'));
    const PROFILE_CONFIG = structuredClone(DEFAULT_PROFILE_CONFIG);
    PROFILE_CONFIG.profiles['Custom Profile'] = { preset: ProfilesRiskPreset.UNKNOWN };

    // Act
    const pol = new ProfilePolicy(PROFILE_CONFIG, $$.mockAuditConfig);
    const policyResult = await pol.run({ targetOrgConnection: await $$.targetOrg.getConnection() });

    // Assert
    expect(policyResult.ignoredEntities).to.deep.equal([
      { name: 'Custom Profile', message: messages.getMessage('preset-unknown', ['Profile']) },
    ]);
    expect(policyResult.auditedEntities).to.deep.equal(['System Administrator', 'Standard User']);
  });

  it('ignores profile from config where metadata resolves to null', async () => {
    // Arrange
    stubUserClassificationRule(newRuleResult('EnforceUserPermissionClassifications'));
    $$.mocks.setQueryMock(
      "SELECT Name,Metadata FROM Profile WHERE Name = 'Custom Profile'",
      path.join(QUERY_RESULTS_DIR, 'profile-with-null-metadata.json')
    );
    const config = structuredClone(DEFAULT_PROFILE_CONFIG);
    config.profiles['Custom Profile'] = { preset: ProfilesRiskPreset.POWER_USER };

    // Act
    const pol = new ProfilePolicy(config, $$.mockAuditConfig);
    const policyResult = await pol.run({ targetOrgConnection: await $$.targetOrg.getConnection() });

    // Assert
    expect(policyResult.ignoredEntities).to.deep.equal([
      { name: 'Custom Profile', message: messages.getMessage('profile-invalid-no-metadata') },
    ]);
    expect(policyResult.auditedEntities).to.deep.equal(['System Administrator', 'Standard User']);
  });

  it('evaluates entities with no violations as compliant', async () => {
    // Arrange
    const mockResult = newRuleResult('EnforceUserPermissionClassifications');
    mockResult.violations.push({ identifier: ['Standard User', 'ViewSetup'], message: 'Irrelevant msg' });
    mockResult.violations.push({ identifier: ['Standard User', 'CustomizeApplication'], message: 'Irrelevant msg' });
    stubUserClassificationRule(mockResult);

    // Act
    const pol = new ProfilePolicy(DEFAULT_PROFILE_CONFIG, $$.mockAuditConfig);
    const policyResult = await pol.run({ targetOrgConnection: $$.targetOrgConnection });

    // Assert
    expect(policyResult.isCompliant).to.be.false;
    const ruleResult = policyResult.executedRules.EnforceUserPermissionClassifications;
    expect(ruleResult.compliantEntities).to.deep.equal(['System Administrator']);
    expect(ruleResult.violatedEntities).to.deep.equal(['Standard User']);
  });

  it('evaluates entities with warnings as compliant', async () => {
    // Arrange
    const mockResult = newRuleResult('EnforceUserPermissionClassifications');
    mockResult.warnings.push({ identifier: ['Standard User', 'ViewSetup'], message: 'Irrelevant msg' });
    mockResult.warnings.push({ identifier: ['Standard User', 'ViewAllData'], message: 'Irrelevant msg' });
    stubUserClassificationRule(mockResult);

    // Act
    const pol = new ProfilePolicy(DEFAULT_PROFILE_CONFIG, $$.mockAuditConfig);
    const policyResult = await pol.run({ targetOrgConnection: $$.targetOrgConnection });

    // Assert
    expect(policyResult.isCompliant).to.be.true;
    const ruleResult = policyResult.executedRules.EnforceUserPermissionClassifications;
    expect(ruleResult.compliantEntities).to.deep.equal(['System Administrator', 'Standard User']);
    expect(ruleResult.violatedEntities).to.deep.equal([]);
  });
});

function loadProfileMetadata(profileFileName: string): ProfileMetadata {
  const content = fs.readFileSync(path.join(QUERY_RESULTS_DIR, profileFileName), 'utf-8');
  const records = JSON.parse(content) as Profile[];
  return records[0].Metadata;
}

class TestProfilesRegistry extends RuleRegistry {
  public constructor() {
    super({
      TestRule: EnforceUserPermsClassificationOnProfiles,
    });
  }
}
