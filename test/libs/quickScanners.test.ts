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
      const result = await UserPermissionScanner.quickScan({
        targetOrg: $$.targetOrgConnection,
        permissions: ['AuthorApex', 'EmailMass', 'ExportReport'],
      });

      // Assert
      expect(Object.keys(result)).to.deep.equal(['AuthorApex', 'EmailMass', 'ExportReport']);
      expect(result.AuthorApex.profiles).to.deep.equal(['System Administrator']);
      expect(result.AuthorApex.permissionSets).to.deep.equal(['Test_Admin_Permission_Set_2']);
      expect(result.EmailMass.profiles).to.deep.equal(['System Administrator', 'Standard User']);
      expect(result.ExportReport.profiles).to.deep.equal(['System Administrator', 'Standard User']);
    });
  });
});
