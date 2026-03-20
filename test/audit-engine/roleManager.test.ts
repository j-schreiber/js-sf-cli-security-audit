import { expect } from 'chai';
import Sinon, { SinonSandbox } from 'sinon';
import { Messages } from '@salesforce/core';
import { AuditRunLifecycleBus } from '../../src/libs/audit-engine/auditRunLifecycle.js';
import { PermissionRiskLevel, UserPrivilegeLevel } from '../../src/libs/audit-engine/index.js';
import RoleManager from '../../src/libs/audit-engine/registry/roles/roleManager.js';
import { PermissionClassifications } from '../../src/libs/audit-engine/registry/shape/schema.js';

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

  describe('allows permission', () => {
    it('falls back to legacy role when no definition is provided', () => {
      // Act
      const rm = new RoleManager(undefined, { userPermissions });

      // Assert
      expect(rm.allowsPermission(UserPrivilegeLevel.STANDARD_USER, 'LowPermName')).to.be.true;
      expect(rm.allowsPermission(UserPrivilegeLevel.POWER_USER, 'LowPermName')).to.be.true;
      expect(rm.allowsPermission(UserPrivilegeLevel.ADMIN, 'LowPermName')).to.be.true;
      expect(rm.allowsPermission(UserPrivilegeLevel.DEVELOPER, 'LowPermName')).to.be.true;
      expect(rm.allowsPermission(UserPrivilegeLevel.UNKNOWN, 'LowPermName')).to.be.false;
      expect(rm.allowsPermission(UserPrivilegeLevel.UNKNOWN, 'UnknownPermName')).to.be.false;
      expect(rm.allowsPermission(UserPrivilegeLevel.STANDARD_USER, 'CriticalPermName')).to.be.false;
      expect(rm.allowsPermission(UserPrivilegeLevel.POWER_USER, 'CriticalPermName')).to.be.false;
      expect(rm.allowsPermission(UserPrivilegeLevel.ADMIN, 'CriticalPermName')).to.be.false;
      expect(rm.allowsPermission(UserPrivilegeLevel.DEVELOPER, 'CriticalPermName')).to.be.true;
      expect(rm.allowsPermission(UserPrivilegeLevel.UNKNOWN, 'CriticalPermName')).to.be.false;
    });

    it('throws exception if role is accessed that does not exist', () => {
      // Act
      const rm = new RoleManager(undefined);

      // Assert
      expect(() => rm.allowsPermission('SOME_CUSTOM_ROLE', 'LowPermName')).to.throw('SOME_CUSTOM_ROLE');
      expect(() => rm.allowsPermission('another custom role', 'LowPermName')).to.throw('another custom role');
    });

    it('denies permission for legacy role that has no classification', () => {
      // Act
      const rm = new RoleManager(undefined);

      // Assert
      expect(rm.allowsPermission(UserPrivilegeLevel.DEVELOPER, 'AnyPermName')).to.be.false;
    });

    it('allows permissions of configured classifications from role definition', () => {
      // Act
      const rm = new RoleManager(
        {
          'My Custom Role': { allowedClassifications: [PermissionRiskLevel.LOW, PermissionRiskLevel.MEDIUM] },
          'My Ops Role': { allowedClassifications: [PermissionRiskLevel.CRITICAL] },
        },
        { userPermissions }
      );

      // Assert
      expect(rm.allowsPermission('My Custom Role', 'LowPermName')).to.be.true;
      expect(rm.allowsPermission('My Custom Role', 'MediumPermName')).to.be.true;
      expect(rm.allowsPermission('My Custom Role', 'HighPermName')).to.be.false;
      expect(rm.allowsPermission('My Custom Role', 'CriticalPermName')).to.be.false;
      expect(rm.allowsPermission('My Ops Role', 'CriticalPermName')).to.be.true;
      expect(rm.allowsPermission('My Ops Role', 'HighPermName')).to.be.false;
    });

    it('ignores duplicate role definitions after normalisation', () => {
      // Arrange
      const resolveListener = SANDBOX.stub();
      AuditRunLifecycleBus.on('resolvewarning', resolveListener);

      // Act
      const rm = new RoleManager(
        {
          'My Custom Role': { allowedClassifications: [PermissionRiskLevel.LOW, PermissionRiskLevel.MEDIUM] },
          MY_CUSTOM_ROLE: { allowedClassifications: [PermissionRiskLevel.CRITICAL] },
        },
        { userPermissions }
      );

      // Assert
      expect(resolveListener.args.flat()).to.deep.equal([
        {
          message: messages.getMessage('DuplicateRoleAfterNormalization', ['My Custom Role', 'MY_CUSTOM_ROLE']),
        },
      ]);
      expect(rm.allowsPermission('My Custom Role', 'LowPermName')).to.be.true;
      expect(rm.allowsPermission('My Custom Role', 'CriticalPermName')).to.be.false;
    });

    it('allows whitelisted permission even though classification does not include', () => {
      // Act
      const rm = new RoleManager(
        {
          'My Custom Role': {
            allowedClassifications: [PermissionRiskLevel.LOW, PermissionRiskLevel.MEDIUM],
            allowedPermissions: ['ViewAllData', 'CustomizeApplication'],
          },
        },
        { userPermissions }
      );

      // Assert
      expect(rm.allowsPermission('My Custom Role', 'HighPermName')).to.be.false;
      expect(rm.allowsPermission('My Custom Role', 'CriticalPermName')).to.be.false;
      expect(rm.allowsPermission('My Custom Role', 'MediumPermName')).to.be.true;
      expect(rm.allowsPermission('My Custom Role', 'ViewAllData')).to.be.true;
      expect(rm.allowsPermission('My Custom Role', 'CustomizeApplication')).to.be.true;
    });

    it('denies blacklisted permission that would be allowed by classification', () => {
      // Act
      const rm = new RoleManager(
        {
          'My Custom Role': {
            allowedClassifications: [PermissionRiskLevel.LOW, PermissionRiskLevel.MEDIUM],
            deniedPermissions: ['MediumPermName'],
          },
        },
        { userPermissions }
      );

      // Assert
      expect(rm.allowsPermission('My Custom Role', 'MediumPermName')).to.be.false;
    });

    it('overrides deny permission with allow permission when both are set', () => {
      // Act
      const rm = new RoleManager(
        {
          'My Custom Role': {
            allowedClassifications: [PermissionRiskLevel.LOW, PermissionRiskLevel.MEDIUM],
            deniedPermissions: ['ViewPublicListViews'],
            allowedPermissions: ['ViewPublicListViews'],
          },
        },
        { userPermissions }
      );

      // Assert
      expect(rm.allowsPermission('My Custom Role', 'ViewPublicListViews')).to.be.false;
    });

    it('denies all permissions for empty custom role (that allows nothing)', () => {
      // Act
      const rm = new RoleManager({ MyEmptyRole: {} }, { userPermissions });

      // Assert
      for (const permName of Object.keys(userPermissions)) {
        expect(rm.allowsPermission('MyEmptyRole', permName)).to.be.false;
      }
    });
  });

  describe('compare', () => {
    it('compares modern roles by config and is superset if all allowed are included', () => {
      // Act
      const rm = new RoleManager(
        {
          PowerUser: {
            allowedClassifications: [PermissionRiskLevel.LOW, PermissionRiskLevel.MEDIUM],
            allowedPermissions: ['HighPermName'],
          },
          RegularUser: {
            allowedClassifications: [PermissionRiskLevel.LOW],
          },
        },
        { userPermissions }
      );

      // Assert
      const powerWithRegular = rm.compare('PowerUser', 'RegularUser');
      expect(powerWithRegular.isSuperset).to.be.true;
      expect(powerWithRegular.missingPermsInOther).to.have.deep.members(['MediumPermName', 'HighPermName']);
      expect(powerWithRegular.missingPermsInThis).to.deep.equal([]);
      const regularWithPower = rm.compare('RegularUser', 'PowerUser');
      expect(regularWithPower.isSuperset).to.be.false;
      expect(regularWithPower.missingPermsInThis).to.have.deep.members(['MediumPermName', 'HighPermName']);
      expect(regularWithPower.missingPermsInOther).to.deep.equal([]);
    });

    it('compares legacy role by ordinal values of allowed permissions', () => {
      // Act
      const rm = new RoleManager(undefined, { userPermissions });

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
      const rm = new RoleManager(undefined, { userPermissions });

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
});
