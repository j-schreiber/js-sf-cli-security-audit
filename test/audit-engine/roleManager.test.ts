import { expect } from 'chai';
import Sinon, { SinonSandbox } from 'sinon';
import { Messages } from '@salesforce/core';
import { ProfileObjectPermissions } from '@jsforce/jsforce-node/lib/api/metadata.js';
import { PermissionRiskLevel, UserPrivilegeLevel } from '../../src/libs/audit-engine/index.js';
import RoleManager from '../../src/libs/audit-engine/registry/roles/roleManager.js';
import { PermissionClassifications } from '../../src/libs/audit-engine/registry/shape/schema.js';
import {
  ExtendedObjectAccessPermissions,
  ProfileLike,
  RoleManagerConfig,
} from '../../src/libs/audit-engine/registry/roles/roleManager.types.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.enforceClassificationPresets');

describe('role manager', () => {
  const SANDBOX: SinonSandbox = Sinon.createSandbox();
  let userPermissions: PermissionClassifications;

  beforeEach(() => {
    userPermissions = {
      UnknownPermName: { classification: PermissionRiskLevel.UNKNOWN },
      LowPermName: { classification: PermissionRiskLevel.LOW },
      MediumPermName: { classification: PermissionRiskLevel.MEDIUM },
      HighPermName: { classification: PermissionRiskLevel.HIGH },
      CriticalPermName: { classification: PermissionRiskLevel.CRITICAL },
      BlockedPermName: { classification: PermissionRiskLevel.BLOCKED },
    };
  });

  afterEach(() => {
    SANDBOX.reset();
  });

  describe('legacy roles', () => {
    it('falls back to legacy role when no definition is provided', () => {
      // Arrange
      const rm = new RoleManager({ controls: { roles: undefined }, shape: { userPermissions } });

      // Act
      const standardUserResult = rm.scanPermissions(
        UserPrivilegeLevel.STANDARD_USER,
        buildProfileLike(['LowPermName', 'CriticalPermName'])
      );
      const devResult = rm.scanPermissions(
        UserPrivilegeLevel.DEVELOPER,
        buildProfileLike(['LowPermName', 'CriticalPermName'])
      );

      // Assert
      expect(standardUserResult.violations).to.deep.equal([
        {
          identifier: ['Test Profile', 'CriticalPermName'],
          message: messages.getMessage('violations.classification-preset-mismatch', ['Critical', 'Standard User']),
        },
      ]);
      expect(standardUserResult.warnings).to.deep.equal([]);
      expect(devResult.violations).to.deep.equal([]);
      expect(devResult.warnings).to.deep.equal([]);
    });

    it('returns error in result if role is accessed that does not exist', () => {
      // Arrange
      const rm = new RoleManager({ controls: { roles: undefined }, shape: { userPermissions } });

      // Act
      const invalidRole = buildProfileLike(['LowPermName', 'CriticalPermName']);
      const result = rm.scanPermissions('SOME_CUSTOM_ROLE', invalidRole);

      // Assert
      expect(result.errors).to.deep.equal([
        {
          identifier: ['Test Profile'],
          message: messages.getMessage('error.failed-to-resolve-role', ['SOME_CUSTOM_ROLE']),
        },
      ]);
    });

    it('allows permission that has no classification for legacy role with warning', () => {
      // Arrange
      const rm = new RoleManager({ controls: { roles: undefined }, shape: { userPermissions } });

      // Act
      const testProfile = buildProfileLike(['LowPermName', 'AnyPermName']);
      const result = rm.scanPermissions(UserPrivilegeLevel.DEVELOPER, testProfile);

      // Assert
      expect(result.violations).to.deep.equal([]);
      expect(result.warnings).to.deep.equal([
        {
          identifier: ['Test Profile', 'AnyPermName'],
          message: messages.getMessage('warnings.permission-not-classified'),
        },
      ]);
    });

    it('compares legacy role by ordinal values of allowed permissions', () => {
      // Act
      const rm = new RoleManager({ controls: { roles: undefined }, shape: { userPermissions } });

      // Assert
      const powerWithRegular = rm.compare('Admin', 'Power User');
      expect(powerWithRegular.isSuperset).to.be.true;
      expect(powerWithRegular.missingPermsInOther).to.have.deep.members(['HighPermName']);
      expect(powerWithRegular.missingPermsInThis).to.deep.equal([]);
      const regularWithPower = rm.compare('Standard User', 'Admin');
      expect(regularWithPower.isSuperset).to.be.false;
      expect(regularWithPower.missingPermsInThis).to.have.deep.members(['MediumPermName', 'HighPermName']);
      expect(regularWithPower.missingPermsInOther).to.deep.equal([]);
    });

    it('compares legacy role by ordinal values even if permissions are identical', () => {
      // Arrange
      // if no "high" perm is present, Admin and Power User are identical
      delete userPermissions['HighPermName'];

      // Act
      const rm = new RoleManager({ controls: { roles: undefined }, shape: { userPermissions } });

      // Assert
      const powerWithRegular = rm.compare('Admin', 'Power User');
      expect(powerWithRegular.isSuperset).to.be.true;
      expect(powerWithRegular.missingPermsInOther).to.deep.equal([]);
      expect(powerWithRegular.missingPermsInThis).to.deep.equal([]);
      const regularWithPower = rm.compare('Power User', 'Admin');
      expect(regularWithPower.isSuperset).to.be.false;
      expect(regularWithPower.missingPermsInThis).to.deep.equal([]);
      expect(regularWithPower.missingPermsInOther).to.deep.equal([]);
    });
  });

  describe('modern roles', () => {
    let testAuditConfig: RoleManagerConfig;

    describe('permissions', () => {
      beforeEach(() => {
        testAuditConfig = {
          controls: {
            roles: {
              'My Custom Role': {
                permissions: { allowedClassifications: [PermissionRiskLevel.LOW, PermissionRiskLevel.MEDIUM] },
              },
              'My Ops Role': { permissions: { allowedClassifications: [PermissionRiskLevel.CRITICAL] } },
              MyComplexRole: {
                permissions: ['AdminPerms', 'HighAndLower'],
              },
              EmptyTestRole: {},
            },
            permissions: {
              AdminPerms: {
                userPermissions: {
                  allowed: ['ApiEnabled', 'ViewSetup'],
                },
                customPermissions: {
                  allowed: ['My_Custom_Perm'],
                },
              },
              HighAndLower: {
                allowedClassifications: [PermissionRiskLevel.LOW, PermissionRiskLevel.MEDIUM, PermissionRiskLevel.HIGH],
              },
              StandardUserOnly: {
                allowedClassifications: [PermissionRiskLevel.LOW, PermissionRiskLevel.MEDIUM],
                userPermissions: {
                  denied: ['ApiEnabled'],
                },
              },
            },
          },
          shape: {
            userPermissions: {
              ...userPermissions,
              ...{
                ApiEnabled: { classification: PermissionRiskLevel.CRITICAL },
                ViewSetup: { classification: PermissionRiskLevel.CRITICAL },
              },
            },
          },
        };
      });

      it('passes root identifier to violations identifier if it is set', () => {
        // Act
        const rm = new RoleManager(testAuditConfig);
        const testProfile = buildProfileLike(['LowPermName', 'HighPermName', 'ViewSetup']);
        const result = rm.scanPermissions('EmptyTestRole', testProfile, ['username@example.com']);

        // Assert
        expect(result.violations).to.have.lengthOf(3);
        expect(result.violations[0].identifier).to.deep.equal(['username@example.com', 'Test Profile', 'LowPermName']);
        expect(result.violations[1].identifier).to.deep.equal(['username@example.com', 'Test Profile', 'HighPermName']);
        expect(result.violations[2].identifier).to.deep.equal(['username@example.com', 'Test Profile', 'ViewSetup']);
      });

      it('returns errors if profile likes have undefined metadata', () => {
        // Act
        const rm = new RoleManager(testAuditConfig);
        const profileLikes: ProfileLike[] = [
          { name: 'Test Profile', type: 'Profile' },
          { name: 'Test_Perm_Set', type: 'PermissionSet' },
        ];
        const result = rm.scanPermissions('My Custom Role', profileLikes);

        // Assert
        expect(result.errors).to.deep.equal([
          {
            identifier: ['Test Profile'],
            message: messages.getMessage('errors.profile-like-has-no-metadata', ['Profile']),
          },
          {
            identifier: ['Test_Perm_Set'],
            message: messages.getMessage('errors.profile-like-has-no-metadata', ['PermissionSet']),
          },
        ]);
      });

      it('prepends root identifier to error identifiers', () => {
        // Act
        const rm = new RoleManager(testAuditConfig);
        const pl: ProfileLike = { name: 'Test Profile', type: 'Profile' };
        const result = rm.scanPermissions('SOME_CUSTOM_ROLE', pl, ['user@example.com']);

        // Assert
        expect(result.errors).to.deep.equal([
          {
            identifier: ['user@example.com', 'Test Profile'],
            message: messages.getMessage('error.failed-to-resolve-role', ['SOME_CUSTOM_ROLE']),
          },
          {
            identifier: ['user@example.com', 'Test Profile'],
            message: messages.getMessage('errors.profile-like-has-no-metadata', ['Profile']),
          },
        ]);
      });

      it('creates one role-resolve error for each profile-like', () => {
        // Act
        const rm = new RoleManager(testAuditConfig);
        const profileLikes: ProfileLike[] = [
          {
            name: 'Test Profile',
            type: 'Profile',
            metadata: wrapUserPermissions(['ApiEnabled']),
          },
          { name: 'Test_Perm_Set', type: 'PermissionSet', metadata: wrapUserPermissions(['ApiEnabled']) },
        ];
        const result = rm.scanPermissions('NonExistentRole', profileLikes, ['user@example.com']);

        // Assert
        expect(result.errors).to.deep.equal([
          {
            identifier: ['user@example.com', 'Test Profile'],
            message: messages.getMessage('error.failed-to-resolve-role', ['NonExistentRole']),
          },
          {
            identifier: ['user@example.com', 'Test_Perm_Set'],
            message: messages.getMessage('error.failed-to-resolve-role', ['NonExistentRole']),
          },
        ]);
      });

      it('allows permissions of configured classifications from role definition', () => {
        // Act
        const rm = new RoleManager(testAuditConfig);
        const testProfile = buildProfileLike(['LowPermName', 'HighPermName', 'ViewSetup']);
        const result = rm.scanPermissions('MyComplexRole', testProfile);

        // Assert
        expect(result.violations).to.deep.equal([]);
        expect(result.warnings).to.deep.equal([]);
      });

      it('denies blacklisted permission that would be allowed by classification', () => {
        // Arrange
        testAuditConfig.controls.roles!['My Ops Role'] = {
          permissions: {
            userPermissions: { denied: ['CriticalPermName'] },
            allowedClassifications: [PermissionRiskLevel.CRITICAL],
          },
        };
        const rm = new RoleManager(testAuditConfig);

        // Act
        const testProfile = buildProfileLike(['CriticalPermName']);
        const result = rm.scanPermissions('My Ops Role', testProfile);

        // Assert
        expect(result.violations).to.have.lengthOf(1);
        expect(result.violations[0]).to.deep.contain({
          identifier: [testProfile.name, 'CriticalPermName'],
        });
      });

      it('throws exception if role references an invalid permission control', () => {
        // Arrange
        testAuditConfig.controls.roles!['MyComplexRole'].permissions = ['InvalidPermRef'];

        // Act
        const expectedMsg = messages.getMessage('RoleReferencesPermissionThatDoesNotExist', [
          'MyComplexRole',
          'InvalidPermRef',
        ]);
        expect(() => new RoleManager(testAuditConfig)).to.throw(expectedMsg);
      });

      it('merges all permission controls to one role definition', () => {
        // Arrange
        testAuditConfig.controls.roles!['MyComplexRole'].permissions = [
          'AdminPerms',
          'HighAndLower',
          'StandardUserOnly',
        ];

        // Act
        const rm = new RoleManager(testAuditConfig);
        const roleDef = rm.getRole('MyComplexRole');

        // Assert
        expect(roleDef.isAllowed({ name: 'LowPermName', type: 'userPermissions' })).to.be.true;
        expect(roleDef.isAllowed({ name: 'MediumPermName', type: 'userPermissions' })).to.be.true;
        expect(roleDef.isAllowed({ name: 'HighPermName', type: 'userPermissions' })).to.be.true;
        expect(roleDef.isAllowed({ name: 'ViewSetup', type: 'userPermissions' })).to.be.true;
        expect(roleDef.isAllowed({ name: 'ApiEnabled', type: 'userPermissions' })).to.be.false;
        expect(roleDef.isAllowed({ name: 'CriticalPermName', type: 'userPermissions' })).to.be.false;
        expect(roleDef.isAllowed({ name: 'My_Custom_Perm', type: 'customPermissions' })).to.be.true;
      });

      // it('ignores duplicate role definitions after normalisation', () => {
      //   // Arrange
      //   const resolveListener = SANDBOX.stub();
      //   AuditRunLifecycleBus.on('resolvewarning', resolveListener);

      //   // Act
      //   const rm = new RoleManager(
      //     {
      //       'My Custom Role': { allowedClassifications: [PermissionRiskLevel.LOW, PermissionRiskLevel.MEDIUM] },
      //       MY_CUSTOM_ROLE: { allowedClassifications: [PermissionRiskLevel.CRITICAL] },
      //     },
      //     { userPermissions }
      //   );

      //   // Assert
      //   expect(resolveListener.args.flat()).to.deep.equal([
      //     {
      //       message: messages.getMessage('DuplicateRoleAfterNormalization', ['My Custom Role', 'MY_CUSTOM_ROLE']),
      //     },
      //   ]);
      //   expect(rm.allowsPermission('My Custom Role', 'LowPermName')).to.be.true;
      //   expect(rm.allowsPermission('My Custom Role', 'CriticalPermName')).to.be.false;
      // });

      it('denies all permissions for empty custom role (that allows nothing)', () => {
        // Act
        const rm = new RoleManager(testAuditConfig);
        const role = rm.getRole('EmptyTestRole');

        // Assert
        for (const permName of Object.keys(userPermissions)) {
          expect(role.isAllowed({ name: permName, type: 'userPermissions' })).to.be.false;
        }
      });

      it('compares modern roles by config and is superset if all allowed are included', () => {
        // Act
        const rm = new RoleManager(testAuditConfig);

        // Assert
        const privilegedWithLess = rm.compare('MyComplexRole', 'My Custom Role');
        expect(privilegedWithLess.isSuperset).to.be.true;
        expect(privilegedWithLess.missingPermsInOther).to.have.deep.members([
          'ApiEnabled',
          'ViewSetup',
          'HighPermName',
        ]);
        expect(privilegedWithLess.missingPermsInThis).to.deep.equal([]);
        const otherWayRound = rm.compare('My Custom Role', 'MyComplexRole');
        expect(otherWayRound.isSuperset).to.be.false;
        expect(otherWayRound.missingPermsInOther).to.deep.equal([]);
        expect(otherWayRound.missingPermsInThis).to.have.deep.members(['ApiEnabled', 'ViewSetup', 'HighPermName']);
      });

      it('denies permission independent of its classification and case-insensitive', () => {
        // Arrange
        testAuditConfig.controls.roles!['My Ops Role'] = {
          permissions: {
            userPermissions: { denied: ['someunclassifiedperm'] },
          },
        };
        const rm = new RoleManager(testAuditConfig);

        // Act
        const testProfile = buildProfileLike(['SomeUnclassifiedPerm']);
        const result = rm.scanPermissions('My Ops Role', testProfile);

        // Assert
        expect(result.violations).to.have.lengthOf(1);
        expect(result.violations[0]).to.deep.contain({
          identifier: [testProfile.name, 'SomeUnclassifiedPerm'],
        });
      });
    });

    describe('object access', () => {
      beforeEach(() => {
        testAuditConfig = {
          controls: {
            roles: {
              CustomRole: {
                strict: true,
                objectAccess: {
                  Contact: {
                    allowCreate: true,
                    allowRead: true,
                    allowEdit: true,
                    allowDelete: false,
                  },
                },
              },
              OpsRole: {
                objectAccess: ['AccountReadOnly'],
              },
              ComplexRole: {
                objectAccess: ['AccountReadOnly', 'CannotDeleteOpps'],
              },
            },
            objectAccess: {
              AccountReadOnly: {
                Account: {
                  allowCreate: false,
                  allowRead: true,
                  allowEdit: false,
                  allowDelete: false,
                },
              },
              CannotDeleteOpps: {
                Opportunity: {
                  allowCreate: true,
                  allowRead: true,
                  allowEdit: true,
                  allowDelete: false,
                },
                Quote: {
                  allowCreate: true,
                  allowRead: true,
                  allowEdit: true,
                  allowDelete: false,
                },
              },
            },
          },
          shape: {},
        };
      });

      it('merges full object access with the last access control', () => {
        // Arrange
        // when object access for a role is resolved, the last access control
        // always takes precedence.
        testAuditConfig.controls.objectAccess!['AccountFullAccess'] = {
          Account: {
            allowRead: true,
            allowEdit: true,
            viewAllFields: true,
          },
        };
        testAuditConfig.controls.roles!['OpsRole'].objectAccess = ['AccountReadOnly', 'AccountFullAccess'];

        // Act
        const rm = new RoleManager(testAuditConfig);
        const accPerms = rm.getRole('OpsRole').getObjectAccess('Account');

        // Assert
        expect(accPerms).to.deep.equal({
          allowRead: true,
          allowEdit: true,
          viewAllFields: true,
          allowDelete: false,
          allowCreate: false,
        });
      });

      it('merges partial object access with the last access control', () => {
        // Arrange
        // does not specify access that was **granted**
        testAuditConfig.controls.objectAccess!['OtherAccountAccess'] = {
          Account: {
            allowEdit: true,
            viewAllFields: true,
          },
        };
        testAuditConfig.controls.roles!['OpsRole'].objectAccess = ['AccountReadOnly', 'OtherAccountAccess'];

        // Act
        const rm = new RoleManager(testAuditConfig);
        const accPerms = rm.getRole('OpsRole').getObjectAccess('Account');

        // Assert
        expect(accPerms).to.deep.equal({
          allowRead: true,
          allowEdit: true,
          viewAllFields: true,
          allowDelete: false,
          allowCreate: false,
        });
      });

      it('allows access to account when role grants the access', () => {
        // Act
        const rm = new RoleManager(testAuditConfig);
        // role allows read only, profile only grants read
        const testProfile = buildProfileForObjectPerms([
          { object: 'Account', allowRead: true, allowEdit: false, allowCreate: false, allowDelete: false },
        ]);
        const result = rm.scanObjectAccess('OpsRole', [testProfile]);

        // Assert
        expect(result.violations).to.deep.equal([]);
        expect(result.warnings).to.deep.equal([]);
        expect(result.errors).to.deep.equal([]);
      });

      it('allows access unspecified object when role is not strict', () => {
        // Act
        const rm = new RoleManager(testAuditConfig);
        // roles does not contain contact, but is not strict
        const testProfile = buildProfileForObjectPerms([
          { object: 'Contact', allowRead: true, allowEdit: false, allowCreate: false, allowDelete: false },
        ]);
        const result = rm.scanObjectAccess('OpsRole', [testProfile]);

        // Assert
        expect(result.violations).to.deep.equal([]);
        expect(result.warnings).to.deep.equal([]);
        expect(result.errors).to.deep.equal([]);
      });

      it('denies access to unspecified object when role is strict', () => {
        // Act
        const rm = new RoleManager(testAuditConfig);
        // roles does not contain Account (only Contact) and is strict
        const testProfile = buildProfileForObjectPerms([
          { object: 'Account', allowRead: true, allowEdit: false, allowCreate: false, allowDelete: false },
        ]);
        const result = rm.scanObjectAccess('CustomRole', [testProfile]);

        // Assert
        expect(result.violations).to.deep.equal([
          {
            identifier: ['Test Profile', 'Account', 'allowRead'],
            message: messages.getMessage('violations.object-access-denied', ['CustomRole']),
          },
        ]);
        expect(result.warnings).to.deep.equal([]);
        expect(result.errors).to.deep.equal([]);
      });

      it('denies access to account when role does not grant the access', () => {
        // Act
        const rm = new RoleManager(testAuditConfig);
        // role allows read only, profile grants read, edit, create
        const testProfile = buildProfileForObjectPerms([
          { object: 'Account', allowRead: true, allowEdit: true, allowCreate: true, allowDelete: false },
        ]);
        const result = rm.scanObjectAccess('OpsRole', [testProfile]);

        // Assert
        expect(result.violations).to.deep.equal([
          {
            identifier: ['Test Profile', 'Account', 'allowCreate'],
            message: messages.getMessage('violations.object-access-denied', ['OpsRole']),
          },
          {
            identifier: ['Test Profile', 'Account', 'allowEdit'],
            message: messages.getMessage('violations.object-access-denied', ['OpsRole']),
          },
        ]);
        expect(result.warnings).to.deep.equal([]);
        expect(result.errors).to.deep.equal([]);
      });

      it('allows granted object permissions when role allows them', () => {
        // Act
        const rm = new RoleManager(testAuditConfig);
        // ensures that the comparison is not "same boolean value" but checks only explicit grant
        const testProfile = buildProfileForObjectPerms([
          { object: 'Contact', allowRead: false, allowEdit: false, allowCreate: false, allowDelete: false },
        ]);
        const result = rm.scanObjectAccess('CustomRole', [testProfile]);

        // Assert
        expect(result.violations).to.deep.equal([]);
        expect(result.warnings).to.deep.equal([]);
        expect(result.errors).to.deep.equal([]);
      });

      it('allows granted "viewAllFields" permission when role allows it', () => {
        // Arrange
        testAuditConfig.controls.objectAccess!['AccountReadOnly']['Account'].viewAllFields = true;

        // Act
        const rm = new RoleManager(testAuditConfig);
        const testProfile = coerceProfileLikeWithExtendedPermissions([
          {
            object: 'Account',
            viewAllFields: true,
            allowRead: true,
            allowCreate: false,
            allowEdit: false,
            allowDelete: false,
          },
        ]);
        const result = rm.scanObjectAccess('OpsRole', [testProfile]);

        // Assert
        expect(result.violations).to.deep.equal([]);
        expect(result.warnings).to.deep.equal([]);
        expect(result.errors).to.deep.equal([]);
      });

      it('denies granted "viewAllFields" permission when role does not allow it', () => {
        // Act
        const rm = new RoleManager(testAuditConfig);
        const testProfile = coerceProfileLikeWithExtendedPermissions([
          {
            object: 'Account',
            viewAllFields: true,
            allowRead: true,
            allowCreate: false,
            allowEdit: false,
            allowDelete: false,
          },
        ]);
        const result = rm.scanObjectAccess('OpsRole', [testProfile]);

        // Assert
        expect(result.violations).to.deep.equal([
          {
            identifier: [testProfile.name, 'Account', 'viewAllFields'],
            message: messages.getMessage('violations.object-access-denied', ['OpsRole']),
          },
        ]);
        expect(result.warnings).to.deep.equal([]);
        expect(result.errors).to.deep.equal([]);
      });
    });
  });
});

function buildProfileLike(enabledUserPerms: string[]): ProfileLike {
  return {
    name: 'Test Profile',
    metadata: wrapUserPermissions(enabledUserPerms),
    type: 'Profile',
  };
}

function wrapUserPermissions(enabledUserPerms: string[]): NonNullable<ProfileLike['metadata']> {
  return {
    userPermissions: enabledUserPerms.map((name) => ({ enabled: true, name })),
    customPermissions: [],
    objectPermissions: [],
  };
}

function buildProfileForObjectPerms(objectPermissions: ProfileObjectPermissions[]): ProfileLike {
  return {
    name: 'Test Profile',
    metadata: {
      userPermissions: [],
      customPermissions: [],
      objectPermissions,
    },
    type: 'Profile',
  };
}

/**
 * The "wrong" type is deliberate: Metadata API returns object permissions with "viewAllFields"
 * property that does not exist in the type schema from jsforce (as of 3.14.10). This allows to
 * to audit for it in a type-safe way.
 *
 * @param objectPermissions
 * @returns
 */
function coerceProfileLikeWithExtendedPermissions(objectPermissions: ExtendedObjectAccessPermissions[]): ProfileLike {
  return {
    name: 'Test Profile',
    type: 'Profile',
    metadata: {
      objectPermissions,
      userPermissions: [],
      customPermissions: [],
    },
  } as unknown as ProfileLike;
}
