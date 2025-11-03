import { expect } from 'chai';
import { PERMISSION_SETS_QUERY, PROFILES_QUERY } from '../../src/libs/core/constants.js';
import UserPermissionScanner from '../../src/libs/quick-scan/userPermissionScanner.js';
import AuditTestContext from '../mocks/auditTestContext.js';

describe('quick scanners', () => {
  const $$ = new AuditTestContext();

  beforeEach(async () => {
    $$.mocks.setQueryMock(PERMISSION_SETS_QUERY, 'resolvable-permission-sets');
    $$.mocks.setQueryMock(PROFILES_QUERY, 'profiles-for-resolve');
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
      });

      // Assert
      expect(Object.keys(result.permissions)).to.deep.equal(['AuthorApex', 'EmailMass', 'ExportReport']);
      expect(result.permissions.AuthorApex.profiles).to.deep.equal(['System Administrator']);
      expect(result.permissions.AuthorApex.permissionSets).to.deep.equal(['Test_Admin_Permission_Set_2']);
      expect(result.permissions.EmailMass.profiles).to.deep.equal(['System Administrator', 'Standard User']);
      expect(result.permissions.ExportReport.profiles).to.deep.equal(['System Administrator', 'Standard User']);
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
      expect(progressListener.args.flat()[2]).to.deep.equal({
        profiles: {
          total: 2,
          resolved: 0,
        },
        permissionSets: {},
        users: {},
        status: 'In Progress',
      });
      expect(progressListener.args.flat()[3]).to.deep.equal({
        profiles: {
          total: 2,
          resolved: 0,
        },
        permissionSets: {
          total: 7,
          resolved: 0,
        },
        users: {},
        status: 'In Progress',
      });
    });
  });
});
