import { expect } from 'chai';
import Sinon, { SinonSandbox } from 'sinon';
import { Messages } from '@salesforce/core';
import { AuditRunLifecycleBus } from '../../src/libs/audit-engine/auditRunLifecycle.js';
import { PermissionRiskLevel, UserPrivilegeLevel } from '../../src/libs/audit-engine/index.js';
import RoleManager from '../../src/libs/audit-engine/registry/roles/roleManager.js';
import LegacyRole from '../../src/libs/audit-engine/registry/roles/legacyRole.js';
import ModernRole from '../../src/libs/audit-engine/registry/roles/modernRole.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.enforceClassificationPresets');

describe('role manager', () => {
  const SANDBOX: SinonSandbox = Sinon.createSandbox();

  afterEach(() => {
    SANDBOX.reset();
  });

  describe('allows permission', () => {
    it('falls back to legacy role when no definition is provided', () => {
      // Act
      const rm = new RoleManager(undefined);

      // Assert
      const lowPerm = { classification: PermissionRiskLevel.LOW };
      const critPerm = { classification: PermissionRiskLevel.CRITICAL };
      const unknownPerm = { classification: PermissionRiskLevel.UNKNOWN };
      expect(rm.allowsPermission(UserPrivilegeLevel.STANDARD_USER, lowPerm)).to.be.true;
      expect(rm.allowsPermission(UserPrivilegeLevel.POWER_USER, lowPerm)).to.be.true;
      expect(rm.allowsPermission(UserPrivilegeLevel.ADMIN, lowPerm)).to.be.true;
      expect(rm.allowsPermission(UserPrivilegeLevel.DEVELOPER, lowPerm)).to.be.true;
      expect(rm.allowsPermission(UserPrivilegeLevel.UNKNOWN, lowPerm)).to.be.false;
      expect(rm.allowsPermission(UserPrivilegeLevel.UNKNOWN, unknownPerm)).to.be.false;
      expect(rm.allowsPermission(UserPrivilegeLevel.STANDARD_USER, critPerm)).to.be.false;
      expect(rm.allowsPermission(UserPrivilegeLevel.POWER_USER, critPerm)).to.be.false;
      expect(rm.allowsPermission(UserPrivilegeLevel.ADMIN, critPerm)).to.be.false;
      expect(rm.allowsPermission(UserPrivilegeLevel.DEVELOPER, critPerm)).to.be.true;
      expect(rm.allowsPermission(UserPrivilegeLevel.UNKNOWN, critPerm)).to.be.false;
    });

    it('denies role that is not in UserPrivilegeLevel for legacy role', () => {
      // Act
      const rm = new RoleManager(undefined);

      // Assert
      const lowPerm = { classification: PermissionRiskLevel.LOW, name: 'AnyPermName' };
      expect(rm.allowsPermission('SOME_CUSTOM_ROLE', lowPerm)).to.be.false;
      expect(rm.allowsPermission('another custom role', lowPerm)).to.be.false;
    });

    it('denies permission for legacy role that has no classification', () => {
      // Act
      const rm = new RoleManager(undefined);

      // Assert
      const undefPerm = { classification: undefined, name: 'AnyPermName' };
      expect(rm.allowsPermission(UserPrivilegeLevel.DEVELOPER, undefPerm)).to.be.false;
    });

    it('allows explicitly configured classification in modern role', () => {
      // Act
      const rm = new RoleManager({
        'My Custom Role': { allowedClassifications: [PermissionRiskLevel.LOW, PermissionRiskLevel.MEDIUM] },
        'My Ops Role': { allowedClassifications: [PermissionRiskLevel.CRITICAL] },
      });

      // Assert
      const lowPerm = { classification: PermissionRiskLevel.LOW, name: 'PermName' };
      const mediumPerm = { classification: PermissionRiskLevel.MEDIUM, name: 'PermName' };
      const highPerm = { classification: PermissionRiskLevel.HIGH, name: 'PermName' };
      const criticalPerm = { classification: PermissionRiskLevel.CRITICAL, name: 'PermName' };
      expect(rm.allowsPermission('My Custom Role', lowPerm)).to.be.true;
      expect(rm.allowsPermission('My Custom Role', mediumPerm)).to.be.true;
      expect(rm.allowsPermission('My Custom Role', highPerm)).to.be.false;
      expect(rm.allowsPermission('My Custom Role', criticalPerm)).to.be.false;
      expect(rm.allowsPermission('My Ops Role', criticalPerm)).to.be.true;
      expect(rm.allowsPermission('My Ops Role', highPerm)).to.be.false;
    });

    it('ignores duplicate role definitions after normalisation', () => {
      // Arrange
      const resolveListener = SANDBOX.stub();
      AuditRunLifecycleBus.on('resolvewarning', resolveListener);

      // Act
      const rm = new RoleManager({
        'My Custom Role': { allowedClassifications: [PermissionRiskLevel.LOW, PermissionRiskLevel.MEDIUM] },
        MY_CUSTOM_ROLE: { allowedClassifications: [PermissionRiskLevel.CRITICAL] },
      });

      // Assert
      const lowPerm = { classification: PermissionRiskLevel.LOW, name: 'PermName' };
      const criticalPerm = { classification: PermissionRiskLevel.CRITICAL, name: 'PermName' };
      expect(resolveListener.args.flat()).to.deep.equal([
        {
          message: messages.getMessage('DuplicateRoleAfterNormalization', ['My Custom Role', 'MY_CUSTOM_ROLE']),
        },
      ]);
      expect(rm.allowsPermission('My Custom Role', lowPerm)).to.be.true;
      expect(rm.allowsPermission('My Custom Role', criticalPerm)).to.be.false;
    });

    it('allows whitelisted permission even though classification does not include', () => {
      // Act
      const rm = new RoleManager({
        'My Custom Role': {
          allowedClassifications: [PermissionRiskLevel.LOW, PermissionRiskLevel.MEDIUM],
          allowedPermissions: ['ViewAllData', 'CustomizeApplication'],
        },
      });

      // Assert
      const allowsViewAllData = rm.allowsPermission('My Custom Role', {
        name: 'ViewAllData',
        classification: PermissionRiskLevel.HIGH,
      });
      expect(allowsViewAllData).to.be.true;
      const allowsCustomizeApp = rm.allowsPermission('My Custom Role', {
        name: 'CustomizeApplication',
        classification: PermissionRiskLevel.CRITICAL,
      });
      expect(allowsCustomizeApp).to.be.true;
    });

    it('allows non-whitelisted permission by classification', () => {
      // Act
      const rm = new RoleManager({
        'My Custom Role': {
          allowedClassifications: [PermissionRiskLevel.LOW, PermissionRiskLevel.MEDIUM],
          allowedPermissions: ['ViewAllData', 'CustomizeApplication'],
        },
      });

      // Assert
      const viewListViews = { classification: PermissionRiskLevel.MEDIUM, name: 'ViewPublicListViews' };
      expect(rm.allowsPermission('My Custom Role', viewListViews)).to.be.true;
    });

    it('denies blacklisted permission that would be allowed by classification', () => {
      // Act
      const rm = new RoleManager({
        'My Custom Role': {
          allowedClassifications: [PermissionRiskLevel.LOW, PermissionRiskLevel.MEDIUM],
          deniedPermissions: ['ViewPublicListViews'],
        },
      });

      // Assert
      const viewListViews = { classification: PermissionRiskLevel.MEDIUM, name: 'ViewPublicListViews' };
      expect(rm.allowsPermission('My Custom Role', viewListViews)).to.be.false;
    });

    it('overrides deny permission with allow permission when both are set', () => {
      // Act
      const rm = new RoleManager({
        'My Custom Role': {
          allowedClassifications: [PermissionRiskLevel.LOW, PermissionRiskLevel.MEDIUM],
          deniedPermissions: ['ViewPublicListViews'],
          allowedPermissions: ['ViewPublicListViews'],
        },
      });

      // Assert
      const viewListViews = { classification: PermissionRiskLevel.MEDIUM, name: 'ViewPublicListViews' };
      expect(rm.allowsPermission('My Custom Role', viewListViews)).to.be.false;
    });
  });

  describe('compares with', () => {
    it('compares legacy roles by their ordinal value', () => {
      // Act
      const devRole = new LegacyRole('Developer');
      const adminRole = new LegacyRole('Admin');
      const adminRole2 = new LegacyRole('Admin');

      // Assert
      const devWithAdmin = devRole.compareWith(adminRole);
      expect(devWithAdmin.isSuperset).to.be.true;
      const adminWithDev = adminRole.compareWith(devRole);
      expect(adminWithDev.isSuperset).to.be.false;
      const adminWithAdmin = adminRole.compareWith(adminRole2);
      expect(adminWithAdmin.isSuperset).to.be.true;
    });

    it('compares modern roles by config and is superset if all allowed are included', () => {
      // Act
      const powerUser = new ModernRole('PowerUser', {
        allowedClassifications: [PermissionRiskLevel.MEDIUM, PermissionRiskLevel.LOW],
      });
      const regularUser = new ModernRole('RegularUser', {
        allowedClassifications: [PermissionRiskLevel.LOW],
      });

      // Assert
      const powerWithRegular = powerUser.compareWith(regularUser);
      expect(powerWithRegular.isSuperset).to.be.true;
      const regularWithPower = regularUser.compareWith(powerUser);
      expect(regularWithPower.isSuperset).to.be.false;
    });

    it('evaluates modern role as superset if it contains more allowedPermissions', () => {
      // Act
      const powerUser = new ModernRole('PowerUser', {
        allowedClassifications: [PermissionRiskLevel.LOW],
        allowedPermissions: ['ApiEnabled'],
      });
      const regularUser = new ModernRole('RegularUser', {
        allowedClassifications: [PermissionRiskLevel.LOW],
      });

      // Assert
      const powerWithRegular = powerUser.compareWith(regularUser);
      expect(powerWithRegular.isSuperset).to.be.true;
      const regularWithPower = regularUser.compareWith(powerUser);
      expect(regularWithPower.isSuperset).to.be.false;
    });

    it('evaluates modern role as superset if it contains fewer deniedPermissions', () => {
      // Act
      const powerUser = new ModernRole('PowerUser', {
        allowedClassifications: [PermissionRiskLevel.LOW],
        deniedPermissions: [],
      });
      const regularUser = new ModernRole('RegularUser', {
        allowedClassifications: [PermissionRiskLevel.LOW],
        deniedPermissions: ['ApiEnabled'],
      });

      // Assert
      const powerWithRegular = powerUser.compareWith(regularUser);
      expect(powerWithRegular.isSuperset).to.be.true;
      const regularWithPower = regularUser.compareWith(powerUser);
      expect(regularWithPower.isSuperset).to.be.false;
    });

    it('evaluates modern role against a role that has undefined denied permissions', () => {
      // Act
      const powerUser = new ModernRole('PowerUser', {
        allowedClassifications: [PermissionRiskLevel.MEDIUM, PermissionRiskLevel.LOW],
      });
      const regularUser = new ModernRole('RegularUser', {
        allowedClassifications: [PermissionRiskLevel.LOW],
        deniedPermissions: ['ApiEnabled'],
      });

      // Assert
      const powerWithRegular = powerUser.compareWith(regularUser);
      expect(powerWithRegular.isSuperset).to.be.true;
      const regularWithPower = regularUser.compareWith(powerUser);
      expect(regularWithPower.isSuperset).to.be.false;
    });
  });
});
