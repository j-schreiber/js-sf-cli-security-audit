import { expect } from 'chai';
import UserPermissionScanner from '../../src/libs/quick-scan/userPermissionScanner.js';
import AuditTestContext from '../mocks/auditTestContext.js';

describe('quick scanners', () => {
  const $$ = new AuditTestContext();

  beforeEach(async () => {
    $$.mocks.mockPermissionSets('resolvable-permission-sets');
    await $$.init();
  });

  afterEach(async () => {
    $$.reset();
  });

  describe('user permissions', () => {
    it('finds existing permission by name in all profiles and permission sets', async () => {
      // Act
      const scanner = new UserPermissionScanner();
      const result = await scanner.quickScan({
        targetOrg: $$.targetOrgConnection,
        permissions: ['AuthorApex', 'EmailMass', 'ExportReport'],
        deepScan: false,
        includeInactive: false,
      });

      // Assert
      expect(result.permissions).to.have.keys(['AuthorApex', 'EmailMass', 'ExportReport']);
      expect(result.permissions.AuthorApex.profiles).to.deep.equal(['System Administrator']);
      expect(result.permissions.AuthorApex.permissionSets).to.deep.equal(['Test_Admin_Permission_Set_2']);
      expect(result.permissions.EmailMass.profiles).to.deep.equal(['System Administrator', 'Standard User']);
      expect(result.permissions.ExportReport.profiles).to.deep.equal(['System Administrator', 'Standard User']);
    });

    it('includes user permissions in scan result when deepScan is enabled', async () => {
      // Arrange
      $$.mocks.mockPermsetAssignments('test-user-assignments', [
        '0054P00000AYPYXQA5',
        '005Pl000001p3HqIAI',
        '0054P00000AaGueQAF',
      ]);

      // Act
      const scanner = new UserPermissionScanner();
      const result = await scanner.quickScan({
        targetOrg: $$.targetOrgConnection,
        permissions: ['AuthorApex', 'EmailMass', 'ExportReport', 'ViewSetup'],
        deepScan: true,
        includeInactive: false,
      });

      // Assert
      expect(result.permissions).to.have.keys(['AuthorApex', 'EmailMass', 'ExportReport', 'ViewSetup']);
      expect(result.permissions.AuthorApex.users).to.have.deep.members([
        {
          username: 'test-user-2@example.de',
          source: 'System Administrator',
          type: 'Profile',
        },
      ]);
      expect(result.permissions.ViewSetup.users).to.have.deep.members([
        {
          username: 'test-user-2@example.de',
          source: 'System Administrator',
          type: 'Profile',
        },
        {
          username: 'test-user-1@example.de',
          source: 'Standard User',
          type: 'Profile',
        },
        {
          username: 'test-user-2@example.de',
          source: 'Test_Admin_Permission_Set_1',
          type: 'Permission Set',
        },
      ]);
    });

    it('emits events to report scan progress', async () => {
      // Arrange
      const scanner = new UserPermissionScanner();
      const progressListener = $$.context.SANDBOX.stub();
      scanner.addListener('progress', progressListener);

      // Act
      await scanner.quickScan({
        targetOrg: $$.targetOrgConnection,
        permissions: ['AuthorApex'],
        deepScan: false,
        includeInactive: false,
      });

      // Assert
      expect(progressListener.callCount).to.equal(7);
      // need to check if this is actually deterministic or if promise
      // resolves are undeterministic even in tests
      expect(progressListener.args.flat()[0]).to.deep.equal({
        profiles: {},
        permissionSets: {},
        users: {},
        status: 'Pending',
      });
      expect(progressListener.args.flat()[1]).to.deep.equal({
        profiles: {},
        permissionSets: {},
        users: {},
        status: 'In Progress',
      });
      expect(progressListener.args.flat()[6]).to.deep.equal({
        profiles: {
          total: 2,
          resolved: 2,
        },
        permissionSets: {
          total: 7,
          resolved: 7,
        },
        users: {},
        status: 'Completed',
      });
    });

    it('emits events to warn invalid permissions', async () => {
      // Arrange
      const scanner = new UserPermissionScanner();
      const warnListener = $$.context.SANDBOX.stub();
      scanner.addListener('permissionNotFound', warnListener);

      // Act
      await scanner.quickScan({
        targetOrg: $$.targetOrgConnection,
        permissions: ['AutorApex', 'SomethingUnknown', 'CustomizeApplication'],
        deepScan: false,
        includeInactive: false,
      });

      // Assert
      expect(warnListener.args.flat()).to.deep.equal([
        { permissionName: 'AutorApex' },
        { permissionName: 'SomethingUnknown' },
      ]);
    });
  });
});
