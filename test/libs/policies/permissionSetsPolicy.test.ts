/* eslint-disable camelcase */
import path from 'node:path';
import { expect } from 'chai';
import { Messages } from '@salesforce/core';
import AuditTestContext, { newRuleResult } from '../../mocks/auditTestContext.js';
import { PermissionRiskLevelPresets } from '../../../src/libs/policies/types.js';
import PermissionSetPolicy from '../../../src/libs/policies/permissionSetPolicy.js';
import { parseAsPermissionset } from '../../../src/libs/core/mdapi/mdapiRetriever.js';
import EnforceUserPermsClassificationOnPermSets from '../../../src/libs/policies/rules/enforceUserPermsClassificationOnPermSets.js';
import { PermSetsPolicyFileContent } from '../../../src/libs/core/file-mgmt/schema.js';
import { PartialPolicyRuleResult } from '../../../src/libs/policies/interfaces/policyRuleInterfaces.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policies.general');

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
    EnforceUserPermissionClassifications: {
      enabled: true,
    },
  },
} as PermSetsPolicyFileContent;

describe('permission sets policy', () => {
  const $$ = new AuditTestContext();

  function stubUserClassificationRule(mockResult: PartialPolicyRuleResult) {
    return $$.context.SANDBOX.stub(EnforceUserPermsClassificationOnPermSets.prototype, 'run').resolves(mockResult);
  }

  beforeEach(async () => {
    await $$.init();
  });

  afterEach(async () => {
    $$.reset();
  });

  it('runs all rules in policy configuration with fully valid config', async () => {
    // Act
    const pol = new PermissionSetPolicy(DEFAULT_PERMSET_CONFIG, $$.mockAuditConfig);
    const policyResult = await pol.run({ targetOrgConnection: await $$.targetOrg.getConnection() });

    // Assert
    expect(policyResult.isCompliant).to.equal(true);
    const executedRuleNames = Object.keys(policyResult.executedRules);
    expect(executedRuleNames).to.deep.equal(['EnforceUserPermissionClassifications']);
  });

  it('resolves permission sets from config to actual perm set metadata from org', async () => {
    // Arrange
    const ruleSpy = stubUserClassificationRule(newRuleResult('EnforceUserPermissionClassifications'));

    // Act
    const pol = new PermissionSetPolicy(DEFAULT_PERMSET_CONFIG, $$.mockAuditConfig);
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
    const pol = new PermissionSetPolicy(PERMSET_CONFIG, $$.mockAuditConfig);
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
