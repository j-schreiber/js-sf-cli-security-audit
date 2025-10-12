/* eslint-disable camelcase */
import path from 'node:path';
import { expect } from 'chai';
import { Messages } from '@salesforce/core';
import AuditTestContext from '../../mocks/auditTestContext.js';
import { PermissionRiskLevelPresets } from '../../../src/libs/policies/types.js';
import AuditRunConfig from '../../../src/libs/policies/interfaces/auditRunConfig.js';
import { PolicyRuleViolation, RuleComponentMessage } from '../../../src/libs/audit/types.js';
import { PermSetsPolicyFileContent } from '../../../src/libs/policies/schema.js';
import PermissionSetPolicy from '../../../src/libs/policies/permissionSetPolicy.js';
import { parseAsPermissionset } from '../../../src/libs/mdapiRetriever.js';
import EnforceClassificationPresetsPermSets from '../../../src/libs/policies/rules/enforceClassificationPresetsPermSets.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policies.general');

const MOCK_AUDIT_CONTEXT = new AuditRunConfig();
const RETRIEVE_DIR = path.join('test', 'mocks', 'data', 'retrieves', 'full-permsets');

const DEFAULT_PERMSET_CONFIG = {
  enabled: true,
  permissionSets: {
    Test_Admin_Permission_Set_1: {
      preset: PermissionRiskLevelPresets.ADMIN,
    },
    Test_Power_User_Permission_Set_1: {
      preset: PermissionRiskLevelPresets.POWER_USER,
    },
  },
  rules: {
    EnforceClassificationPresets: {
      enabled: true,
    },
  },
} as PermSetsPolicyFileContent;

const MOCK_RULE_RESULT = {
  ruleName: 'EnforceClassificationPresets',
  isCompliant: true,
  violations: new Array<PolicyRuleViolation>(),
  mutedViolations: [],
  warnings: new Array<RuleComponentMessage>(),
  errors: [],
};

describe('permission sets policy', () => {
  const $$ = new AuditTestContext();

  beforeEach(async () => {
    await $$.init();
  });

  afterEach(async () => {
    $$.reset();
  });

  it('runs all rules in policy configuration with fully valid config', async () => {
    // Act
    const pol = new PermissionSetPolicy(DEFAULT_PERMSET_CONFIG, MOCK_AUDIT_CONTEXT);
    const policyResult = await pol.run({ targetOrgConnection: await $$.targetOrg.getConnection() });

    // Assert
    expect(policyResult.isCompliant).to.equal(true);
    const executedRuleNames = Object.keys(policyResult.executedRules);
    expect(executedRuleNames).to.deep.equal(['EnforceClassificationPresets']);
  });

  it('resolves permission sets from config to actual perm set metadata from org', async () => {
    // Arrange
    const ruleSpy = $$.context.SANDBOX.stub(EnforceClassificationPresetsPermSets.prototype, 'run').resolves(
      MOCK_RULE_RESULT
    );

    // Act
    const pol = new PermissionSetPolicy(DEFAULT_PERMSET_CONFIG, MOCK_AUDIT_CONTEXT);
    const policyResult = await pol.run({ targetOrgConnection: await $$.targetOrg.getConnection() });

    // Assert
    const adminPermset = parseAsPermissionset(
      path.join(RETRIEVE_DIR, 'Test_Admin_Permission_Set_1.permissionset-meta.xml')
    );
    const poweruserPermset = parseAsPermissionset(
      path.join(RETRIEVE_DIR, 'Test_Power_User_Permission_Set_1.permissionset-meta.xml')
    );
    const expectedResolvedEntities = {
      Test_Admin_Permission_Set_1: {
        preset: 'Admin',
        name: 'Test_Admin_Permission_Set_1',
        metadata: adminPermset,
      },
      Test_Power_User_Permission_Set_1: {
        preset: 'Power User',
        name: 'Test_Power_User_Permission_Set_1',
        metadata: poweruserPermset,
      },
    };
    expect(ruleSpy.args.flat()[0]).to.deep.contain({
      resolvedEntities: expectedResolvedEntities,
    });
    expect(policyResult.auditedEntities).to.deep.equal(Object.keys(expectedResolvedEntities));
    expect(policyResult.ignoredEntities.length).to.equal(0);
  });

  it('ignores permission set from config that cannot be resolved from target org', async () => {
    // Arrange
    const PERMSET_CONFIG = structuredClone(DEFAULT_PERMSET_CONFIG);
    PERMSET_CONFIG.permissionSets['Test_Admin_Permission_Set_2'] = { preset: PermissionRiskLevelPresets.UNKNOWN };
    PERMSET_CONFIG.permissionSets['An_Unknown_Permission_Set'] = { preset: PermissionRiskLevelPresets.STANDARD_USER };

    // Act
    const pol = new PermissionSetPolicy(PERMSET_CONFIG, MOCK_AUDIT_CONTEXT);
    const policyResult = await pol.run({ targetOrgConnection: await $$.targetOrg.getConnection() });

    // Assert
    expect(policyResult.auditedEntities).to.deep.equal([
      'Test_Admin_Permission_Set_1',
      'Test_Power_User_Permission_Set_1',
    ]);
    expect(policyResult.ignoredEntities).to.deep.equal([
      { name: 'Test_Admin_Permission_Set_2', message: messages.getMessage('preset-unknown', ['Permission Set']) },
      { name: 'An_Unknown_Permission_Set', message: messages.getMessage('entity-not-found') },
    ]);
  });
});
