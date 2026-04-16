import { expect } from 'chai';
import Sinon, { SinonSandbox } from 'sinon';
import { Messages } from '@salesforce/core';
import { PermissionRiskLevel, UserPrivilegeLevel } from '../../src/libs/audit-engine/index.js';
import RoleManager from '../../src/libs/audit-engine/registry/roles/roleManager.js';
import { PermissionClassifications } from '../../src/libs/audit-engine/registry/shape/schema.js';
import {
  ResolvedProfileLike,
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
      const standardUserResult = rm.scanProfileLike(
        buildProfileLike(UserPrivilegeLevel.STANDARD_USER, ['LowPermName', 'CriticalPermName'])
      );
      const devResult = rm.scanProfileLike(
        buildProfileLike(UserPrivilegeLevel.DEVELOPER, ['LowPermName', 'CriticalPermName'])
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

    it('throws exception if role is accessed that does not exist', () => {
      // Arrange
      const rm = new RoleManager({ controls: { roles: undefined }, shape: { userPermissions } });

      // Act
      const invalidRole = buildProfileLike('SOME_CUSTOM_ROLE', ['LowPermName', 'CriticalPermName']);

      // Assert
      expect(() => rm.scanProfileLike(invalidRole)).to.throw('SOME_CUSTOM_ROLE');
    });

    it('allows permission that has no classification for legacy role with warning', () => {
      // Arrange
      const rm = new RoleManager({ controls: { roles: undefined }, shape: { userPermissions } });

      // Act
      const testProfile = buildProfileLike(UserPrivilegeLevel.DEVELOPER, ['LowPermName', 'AnyPermName']);
      const result = rm.scanProfileLike(testProfile);

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

    it('allows permissions of configured classifications from role definition', () => {
      // Act
      const rm = new RoleManager(testAuditConfig);
      const testProfile = buildProfileLike('MyComplexRole', ['LowPermName', 'HighPermName', 'ViewSetup']);
      const result = rm.scanProfileLike(testProfile);

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
      const testProfile = buildProfileLike('My Ops Role', ['CriticalPermName']);
      const result = rm.scanProfileLike(testProfile);

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
      testAuditConfig.controls.roles!['MyComplexRole'].permissions = ['AdminPerms', 'HighAndLower', 'StandardUserOnly'];

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
      expect(privilegedWithLess.missingPermsInOther).to.have.deep.members(['ApiEnabled', 'ViewSetup', 'HighPermName']);
      expect(privilegedWithLess.missingPermsInThis).to.deep.equal([]);
      const otherWayRound = rm.compare('My Custom Role', 'MyComplexRole');
      expect(otherWayRound.isSuperset).to.be.false;
      expect(otherWayRound.missingPermsInOther).to.deep.equal([]);
      expect(otherWayRound.missingPermsInThis).to.have.deep.members(['ApiEnabled', 'ViewSetup', 'HighPermName']);
    });
  });
});

function buildProfileLike(roleName: string, enabledUserPerms: string[]): ResolvedProfileLike {
  return {
    name: 'Test Profile',
    role: roleName,
    metadata: {
      userPermissions: enabledUserPerms.map((name) => ({ enabled: true, name })),
      customPermissions: [],
    },
  };
}
