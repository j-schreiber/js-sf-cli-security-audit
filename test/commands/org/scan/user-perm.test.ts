import { expect } from 'chai';
import OrgUserPermScan from '../../../../src/commands/org/scan/user-perms.js';
import AuditTestContext from '../../../mocks/auditTestContext.js';
import UserPermissionScanner from '../../../../src/libs/quick-scan/userPermissionScanner.js';

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
});
