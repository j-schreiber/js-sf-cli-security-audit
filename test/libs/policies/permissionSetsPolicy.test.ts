/* eslint-disable camelcase */
import path from 'node:path';
import { expect } from 'chai';
import { Messages } from '@salesforce/core';
import AuditTestContext, { newRuleResult } from '../../mocks/auditTestContext.js';
import PermissionSetPolicy from '../../../src/libs/core/policies/permissionSetPolicy.js';
import { NamedTypesRegistry } from '../../../src/libs/core/mdapi/mdapiRetriever.js';
import { BasePolicyFileContent } from '../../../src/libs/core/file-mgmt/schema.js';
import { UserPrivilegeLevel } from '../../../src/libs/core/policy-types.js';
import { PartialPolicyRuleResult } from '../../../src/libs/core/registries/types.js';
import EnforcePermissionsOnProfileLike from '../../../src/libs/core/registries/rules/enforcePermissionsOnProfileLike.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policies.general');

const RETRIEVE_DIR = path.join('test', 'mocks', 'data', 'retrieves', 'full-permsets');

const DEFAULT_PERMSET_CONFIG: BasePolicyFileContent = {
  enabled: true,
  rules: {
    EnforcePermissionClassifications: {
      enabled: true,
    },
  },
};

describe('permission sets policy', () => {
  const $$ = new AuditTestContext();

  function stubUserClassificationRule(mockResult: PartialPolicyRuleResult) {
    return $$.context.SANDBOX.stub(EnforcePermissionsOnProfileLike.prototype, 'run').resolves(mockResult);
  }

  beforeEach(async () => {
    $$.mockAuditConfig.classifications = {
      permissionSets: {
        content: {
          permissionSets: {
            Test_Admin_Permission_Set_1: {
              role: UserPrivilegeLevel.ADMIN,
            },
            Test_Power_User_Permission_Set_1: {
              role: UserPrivilegeLevel.POWER_USER,
            },
          },
        },
      },
    };
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
    expect(executedRuleNames).to.deep.equal(['EnforcePermissionClassifications']);
  });

  it('resolves permission sets from config to actual perm set metadata from org', async () => {
    // Arrange
    const ruleSpy = stubUserClassificationRule(newRuleResult('EnforcePermissionClassifications'));

    // Act
    const pol = new PermissionSetPolicy(DEFAULT_PERMSET_CONFIG, $$.mockAuditConfig);
    const policyResult = await pol.run({ targetOrgConnection: await $$.targetOrg.getConnection() });

    // Assert
    const adminPermset = NamedTypesRegistry.PermissionSet.parse(
      path.join(RETRIEVE_DIR, 'Test_Admin_Permission_Set_1.permissionset-meta.xml')
    );
    const poweruserPermset = NamedTypesRegistry.PermissionSet.parse(
      path.join(RETRIEVE_DIR, 'Test_Power_User_Permission_Set_1.permissionset-meta.xml')
    );
    const expectedResolvedEntities = {
      Test_Admin_Permission_Set_1: {
        role: 'Admin',
        name: 'Test_Admin_Permission_Set_1',
        metadata: adminPermset,
      },
      Test_Power_User_Permission_Set_1: {
        role: 'Power User',
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
    const mockedPermsets = $$.mockAuditConfig.classifications.permissionSets!.content.permissionSets;
    mockedPermsets['Test_Admin_Permission_Set_N'] = { role: UserPrivilegeLevel.UNKNOWN };
    mockedPermsets['An_Unknown_Permission_Set'] = { role: UserPrivilegeLevel.STANDARD_USER };

    // Act
    const pol = new PermissionSetPolicy(PERMSET_CONFIG, $$.mockAuditConfig);
    const policyResult = await pol.run({ targetOrgConnection: await $$.targetOrg.getConnection() });

    // Assert
    expect(policyResult.auditedEntities).to.deep.equal([
      'Test_Admin_Permission_Set_1',
      'Test_Power_User_Permission_Set_1',
    ]);
    expect(policyResult.ignoredEntities).to.deep.equal([
      { name: 'Test_Admin_Permission_Set_N', message: messages.getMessage('preset-unknown', ['Permission Set']) },
      { name: 'An_Unknown_Permission_Set', message: messages.getMessage('entity-not-found') },
    ]);
  });
});
