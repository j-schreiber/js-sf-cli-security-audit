/* eslint-disable camelcase */
import { expect } from 'chai';
import { Messages } from '@salesforce/core';
import AuditTestContext, { newRuleResult } from '../../mocks/auditTestContext.js';
import PermissionSetPolicy from '../../../src/libs/core/policies/permissionSetPolicy.js';
import { BasePolicyFileContent } from '../../../src/libs/core/file-mgmt/schema.js';
import { UserPrivilegeLevel } from '../../../src/libs/core/policy-types.js';
import { PartialPolicyRuleResult } from '../../../src/libs/core/registries/types.js';
import EnforcePermissionsOnProfileLike from '../../../src/libs/core/registries/rules/enforcePermissionsOnProfileLike.js';
import { parsePermSetFromFile } from '../../mocks/testHelpers.js';
import { PERMISSION_SETS_QUERY } from '../../../src/salesforce/repositories/perm-sets/queries.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policies.general');

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
    $$.mocks.setQueryMock(PERMISSION_SETS_QUERY, 'resolvable-permission-sets');
    await $$.init();
  });

  afterEach(async () => {
    $$.reset();
  });

  it('runs all rules in policy configuration with fully valid config', async () => {
    // Act
    const pol = new PermissionSetPolicy(DEFAULT_PERMSET_CONFIG, $$.mockAuditConfig);
    const policyResult = await pol.run({ targetOrgConnection: $$.targetOrgConnection });

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
    const policyResult = await pol.run({ targetOrgConnection: $$.targetOrgConnection });

    // Assert
    const adminPermset = parsePermSetFromFile('Test_Admin_Permission_Set_1');
    const poweruserPermset = parsePermSetFromFile('Test_Power_User_Permission_Set_1');
    const expectedResolvedEntities = {
      Test_Admin_Permission_Set_1: {
        isCustom: false,
        role: 'Admin',
        name: 'Test_Admin_Permission_Set_1',
        metadata: adminPermset,
      },
      Test_Power_User_Permission_Set_1: {
        isCustom: true,
        role: 'Power User',
        name: 'Test_Power_User_Permission_Set_1',
        metadata: poweruserPermset,
      },
    };
    expect(ruleSpy.args.flat()[0]).to.deep.contain({
      resolvedEntities: expectedResolvedEntities,
    });
    expect(policyResult.auditedEntities).to.deep.equal(Object.keys(expectedResolvedEntities));
    // query returns 7 perm sets on org, but only 2 are classified
    expect(policyResult.ignoredEntities.length).to.equal(5);
  });

  it('ignores permission set from config that cannot be resolved from target org', async () => {
    // Arrange
    $$.mockPermSetClassifications({
      Test_Admin_Permission_Set_1: { role: UserPrivilegeLevel.ADMIN },
      An_Unknown_Permission_Set: { role: UserPrivilegeLevel.STANDARD_USER },
    });

    // Act
    const pol = new PermissionSetPolicy(DEFAULT_PERMSET_CONFIG, $$.mockAuditConfig);
    const policyResult = await pol.run({ targetOrgConnection: $$.targetOrgConnection });

    // Assert
    expect(policyResult.auditedEntities).to.deep.equal(['Test_Admin_Permission_Set_1']);
    expect(policyResult.ignoredEntities).to.deep.include.members([
      { name: 'An_Unknown_Permission_Set', message: messages.getMessage('entity-not-found') },
      { name: 'Test_Admin_Permission_Set_2', message: messages.getMessage('entity-not-classified') },
    ]);
  });
});
