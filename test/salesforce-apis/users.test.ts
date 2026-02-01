import { expect, assert } from 'chai';
import AuditTestContext from '../mocks/auditTestContext.js';
import { Users } from '../../src/salesforce/index.js';
import { buildPermsetAssignmentsQuery } from '../../src/salesforce/repositories/users/queries.js';
import { parsePermSetFromFile, parseProfileFromFile } from '../mocks/testHelpers.js';

describe('users resolve', () => {
  const $$ = new AuditTestContext();
  // directly copied from "queryResults/active-users.json"
  const testUserIds = ['0054P00000AYPYXQA5', '005Pl000001p3HqIAI', '0054P00000AaGueQAF'];

  beforeEach(async () => {
    await $$.init();
  });

  afterEach(async () => {
    $$.reset();
  });

  it('resolves all users that exist on the org with default opts', async () => {
    // Act
    const repo = new Users($$.targetOrgConnection);
    const users = await repo.resolve();

    // Assert
    expect(users.size).to.equal(3);
    expect(users.has('test-user-1@example.de')).to.be.true;
    expect(users.has('test-user-2@example.de')).to.be.true;
    for (const user of users.values()) {
      expect(user.logins).to.be.undefined;
    }
  });

  it('resolves all users that exist on the org with login history', async () => {
    // Act
    const repo = new Users($$.targetOrgConnection);
    const users = await repo.resolve({ withLoginHistory: true, loginHistoryDaysToAnalyse: 14 });

    // Assert
    expect(users.size).to.equal(3);
    expect(users.get('test-user-1@example.de')).to.deep.equal({
      // eslint-disable-next-line unicorn/numeric-separators-style
      createdDate: 1760011200000,
      lastLogin: undefined,
      logins: [],
      profileName: 'Standard User',
      userId: '005Pl000001p3HqIAI',
      username: 'test-user-1@example.de',
      isActive: true,
    });
    expect(users.has('test-user-2@example.de')).to.be.true;
    for (const user of users.values()) {
      expect(user.logins).not.to.be.undefined;
    }
  });

  it('resolves assigned permission sets to existing users from target org', async () => {
    // Arrange
    // has assignments for test-user-2@example.de
    $$.mocks.setQueryMock(buildPermsetAssignmentsQuery(testUserIds), 'test-user-assignments');

    // Act
    const repo = new Users($$.targetOrgConnection);
    const users = await repo.resolve({ withPermissions: true });

    // Assert
    expect(users.size).to.equal(3);
    assert.isDefined(users.get('test-user-2@example.de'));
    const mockedUser = users.get('test-user-2@example.de')!;
    expect(mockedUser.assignments!.length).to.equal(2);
    expect(mockedUser.assignments![0]).to.deep.equal({
      permissionSetIdentifier: 'Test_Admin_Permission_Set_1',
      permissionSetSource: 'direct',
    });
  });

  it('resolves users with permission set assignments with metadata from target org', async () => {
    // Arrange
    // has assignments for test-user-2@example.de
    $$.mocks.setQueryMock(buildPermsetAssignmentsQuery(testUserIds), 'test-user-assignments');

    // Act
    const repo = new Users($$.targetOrgConnection);
    const users = await repo.resolve({ withPermissions: true, withPermissionsMetadata: true });

    // Assert
    expect(users.size).to.equal(3);
    assert.isDefined(users.get('test-user-2@example.de'));
    const mockedUser = users.get('test-user-2@example.de')!;
    expect(mockedUser.assignments!.length).to.equal(2);
    expect(mockedUser.assignments![0]).to.deep.equal({
      permissionSetIdentifier: 'Test_Admin_Permission_Set_1',
      permissionSetSource: 'direct',
      metadata: parsePermSetFromFile('Test_Admin_Permission_Set_1'),
    });
    expect(mockedUser.assignments![1]).to.deep.equal({
      permissionSetIdentifier: 'Test_Power_User_Permission_Set_1',
      permissionSetSource: 'direct',
      metadata: parsePermSetFromFile('Test_Power_User_Permission_Set_1'),
    });
  });

  it('resolves empty list of assignments for all users if they have no assignments', async () => {
    // Arrange
    $$.mocks.setQueryMock(buildPermsetAssignmentsQuery(testUserIds), 'empty');

    // Act
    const repo = new Users($$.targetOrgConnection);
    const users = await repo.resolve({ withPermissions: true, withPermissionsMetadata: true });

    // Assert
    for (const usr of users.values()) {
      expect(usr.assignments).to.deep.equal([]);
    }
  });

  it('resolves profile metadata for user if resolved with metadata', async () => {
    // Arrange
    $$.mocks.setQueryMock(buildPermsetAssignmentsQuery(testUserIds), 'empty');

    // Act
    const repo = new Users($$.targetOrgConnection);
    const users = await repo.resolve({ withPermissions: true, withPermissionsMetadata: true });

    // Assert
    expect(users.get('test-user-1@example.de')?.profileMetadata).to.deep.equal(
      parseProfileFromFile('standard-profile-with-metadata')
    );
    // audit context method does not post-process;
    // equal() would fail due to missing properties
    expect(users.get('test-user-2@example.de')?.profileMetadata).to.deep.contain(
      parseProfileFromFile('admin-profile-with-metadata')
    );
  });
});
