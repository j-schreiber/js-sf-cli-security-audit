import { expect, assert } from 'chai';
import { Messages } from '@salesforce/core';
import OrgUserPermScan from '../../src/commands/org/scan/user-perms.js';
import AuditTestContext from '../mocks/auditTestContext.js';
import UserPermissionScanner from '../../src/libs/quick-scan/userPermissionScanner.js';
import { QuickScanResult } from '../../src/libs/quick-scan/types.js';
import { assertSfError } from '../mocks/testHelpers.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'org.scan.user-perms');

describe('org scan user-perm', () => {
  const $$ = new AuditTestContext();

  beforeEach(async () => {
    await $$.init();
  });

  afterEach(async () => {
    $$.reset();
  });

  it('reports results from quick scan result in command JSON', async () => {
    // Arrange
    const mockResult = {
      permissions: {
        CustomizeApplication: {
          profiles: ['System Administrator', 'Custom Administrator'],
          permissionSets: ['My_Test_Perm_Set'],
        },
      },
      scannedProfiles: [],
      scannedPermissionSets: [],
    };
    const scannerMock = $$.context.SANDBOX.stub(UserPermissionScanner.prototype, 'quickScan').resolves(mockResult);

    // Act
    const result = await OrgUserPermScan.run([
      '--target-org',
      $$.targetOrg.username,
      '--name',
      'CustomizeApplication',
      '--json',
    ]);

    // Assert
    // ensure contract - all input params are passed to lib
    expect(scannerMock.callCount).to.equal(1);
    const callArgs = scannerMock.args.flat()[0];
    expect(callArgs.targetOrg.getUsername()).to.equal($$.targetOrgConnection.getUsername());
    expect(callArgs.permissions).to.deep.equal(['CustomizeApplication']);
    expect(result).to.equal(mockResult);
  });

  it('formats results from quick scan result as tables in stdout', async () => {
    // Arrange
    const mockResult = {
      permissions: {
        CustomizeApplication: {
          profiles: ['System Administrator', 'Custom Administrator'],
          permissionSets: ['My_Test_Perm_Set'],
        },
        AuthorApex: {
          profiles: ['Custom Administrator'],
          permissionSets: [],
        },
        UseAnyApiClient: {
          profiles: [],
          permissionSets: [],
        },
      },
      scannedProfiles: [],
      scannedPermissionSets: [],
    };
    $$.context.SANDBOX.stub(UserPermissionScanner.prototype, 'quickScan').resolves(mockResult);

    // Act
    await OrgUserPermScan.run([
      '--target-org',
      $$.targetOrg.username,
      '--name',
      'CustomizeApplication',
      '--name',
      'AuthorApex',
      '--name',
      'UseAnyApiClient',
    ]);

    // Assert
    // 1 call for summary, 2 calls for the detail tables that are not empty
    expect($$.sfCommandStubs.table.callCount).to.equal(3);
    expect($$.sfCommandStubs.table.args.flat()[0]).to.deep.contain({
      data: [
        { permissionName: 'CustomizeApplication', profiles: 2, permissionSets: 1 },
        { permissionName: 'AuthorApex', profiles: 1, permissionSets: 0 },
        { permissionName: 'UseAnyApiClient', profiles: 0, permissionSets: 0 },
      ],
    });
    expect($$.sfCommandStubs.table.args.flat()[1]).to.deep.contain({
      title: 'CustomizeApplication',
      data: [
        { entityName: 'System Administrator', type: 'Profile' },
        { entityName: 'Custom Administrator', type: 'Profile' },
        { entityName: 'My_Test_Perm_Set', type: 'Permission Set' },
      ],
    });
  });

  it('formats permission assignments from user results as table', async () => {
    // Arrange
    const mockResult: QuickScanResult = {
      permissions: {
        ViewSetup: {
          profiles: ['System Administrator', 'Custom Administrator'],
          permissionSets: ['My_Test_Perm_Set'],
          users: [
            { username: 'test1@example.com', source: 'My_Test_Perm_Set', type: 'Permission Set' },
            { username: 'test1@example.com', source: 'System Administrator', type: 'Profile' },
            { username: 'test2@example.com', source: 'My_Test_Perm_Set_2', type: 'Permission Set' },
            { username: 'test2@example.com', source: 'My_Test_Perm_Set', type: 'Permission Set' },
          ],
        },
      },
      scannedProfiles: [],
      scannedPermissionSets: [],
    };
    $$.context.SANDBOX.stub(UserPermissionScanner.prototype, 'quickScan').resolves(mockResult);

    // Act
    await OrgUserPermScan.run(['--target-org', $$.targetOrg.username, '--name', 'ViewSetup', '--deep-scan']);

    // Assert
    // 1 call for summary, 3 calls for details tables
    const summaryTable = $$.sfCommandStubs.table.args.flat()[0];
    expect(summaryTable).to.deep.contain({
      data: [{ permissionName: 'ViewSetup', profiles: 2, permissionSets: 1, assignments: 4 }],
    });
    const usersTable = $$.sfCommandStubs.table.args.flat()[2];
    expect(usersTable.title).to.equal('ViewSetup (Assignments)');
    expect(usersTable.data).to.deep.equal([
      { username: 'test1@example.com', source: 'System Administrator', type: 'Profile' },
      { username: 'test1@example.com', source: 'My_Test_Perm_Set', type: 'Permission Set' },
      { username: 'test2@example.com', source: 'My_Test_Perm_Set', type: 'Permission Set' },
      { username: 'test2@example.com', source: 'My_Test_Perm_Set_2', type: 'Permission Set' },
    ]);
  });

  it('ignores empty user permission assignments in results', async () => {
    // Arrange
    const mockResult: QuickScanResult = {
      permissions: {
        ViewSetup: {
          profiles: [],
          permissionSets: [],
          users: [],
        },
      },
      scannedProfiles: [],
      scannedPermissionSets: [],
    };
    $$.context.SANDBOX.stub(UserPermissionScanner.prototype, 'quickScan').resolves(mockResult);

    // Act
    await OrgUserPermScan.run(['--target-org', $$.targetOrg.username, '--name', 'ViewSetup', '--deep-scan']);

    // Assert
    expect($$.sfCommandStubs.table.callCount).to.equal(1);
  });

  it('prints warning if permission does not exist on target org', async () => {
    // Act
    const result = await OrgUserPermScan.run(['--target-org', $$.targetOrg.username, '--name', 'SomethingUnknown']);

    // Assert
    expect($$.sfCommandStubs.warn.args.flat()).to.deep.equal([
      messages.createWarning('PermissionNotFound', ['SomethingUnknown']),
    ]);
    expect($$.sfCommandStubs.table.callCount).to.equal(0);
    expect(result.permissions).to.not.have.key('SomethingUnknown');
  });

  it('includes inactive users and adds info to users table', async () => {
    // Arrange
    $$.mocks.mockUsers('all-user-details', undefined, false);

    // Act
    const result = await OrgUserPermScan.run([
      '--target-org',
      $$.targetOrg.username,
      '--name',
      'AuthorApex',
      '--deep-scan',
      '--include-inactive',
    ]);

    // Assert
    const users = result.permissions.AuthorApex.users;
    assert.isDefined(users);
    for (const user of users.values()) {
      assert.isDefined(user.isActive);
    }
    expect($$.sfCommandStubs.table.callCount).to.equal(3);
    const assignmentsTable = $$.sfCommandStubs.table.args.flat()[2];
    expect(assignmentsTable.data).to.deep.equal(users);
  });

  it('does not show isActive flag when inactive users are not included', async () => {
    // Act
    const result = await OrgUserPermScan.run([
      '--target-org',
      $$.targetOrg.username,
      '--name',
      'AuthorApex',
      '--deep-scan',
    ]);

    // Assert
    expect($$.sfCommandStubs.table.callCount).to.equal(3);
    const users = result.permissions.AuthorApex.users;
    assert.isDefined(users);
    for (const user of users.values()) {
      assert.isUndefined(user.isActive);
    }
  });

  it('does not allow --include-inactive without --deep-scan', async () => {
    // Act
    try {
      await OrgUserPermScan.run(['--target-org', $$.targetOrg.username, '--name', 'AuthorApex', '--include-inactive']);
      assert.fail('Expected exception, but succeeded');
    } catch (error) {
      // thrown error is oclif internal and configured in "dependsOn" of the flag
      // therefore, we do not over-assert and only check, that the dependend flag
      // appears in the message.
      assertSfError(error, '', '--deep-scan');
    }
  });
});
