import { expect, assert } from 'chai';
import AuditTestContext from '../mocks/auditTestContext.js';
import { Users } from '../../src/salesforce/index.js';
import { parsePermSetFromFile, parseProfileFromFile } from '../mocks/testHelpers.js';

describe('users resolve', () => {
  const $$ = new AuditTestContext();

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
    $$.mocks.mockUsers('active-user-details');

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
    $$.mocks.mockUsers('active-user-details');

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
    $$.mocks.mockUsers('active-user-details', (record) => ({ ...record, PermissionSetAssignments: null }));

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
    $$.mocks.mockUsers('active-user-details');

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

  it('includes inactive users when flag is set', async () => {
    // Arrange
    $$.mocks.mockUsers('all-user-details', undefined);

    // Act
    const repo = new Users($$.targetOrgConnection);
    const users = await repo.resolve({ includeInactive: true });

    // Assert
    expect(users.size).to.equal(3);
    const inactiveUser = users.get('guest-user@example.de');
    assert.isDefined(inactiveUser);
    expect(inactiveUser.isActive).to.be.false;
  });

  it('reduces users batch size for logins when initial query throws EXCEEDED_ID_LIMIT', async () => {
    // Arrange
    // default query with all users in context
    const { queryString } = $$.mocks.mockLoginHistory('logins-with-browser-only');
    $$.mocks.queryErrors[queryString] = {
      errorCode: 'EXCEEDED_ID_LIMIT',
      data: { message: 'Too many ids', errorCode: 'EXCEEDED_ID_LIMIT' },
    };
    // recursive batch-reduce uses Math.floor(), so 3 users create chunkSize = 1
    for (const userId of Object.keys($$.mocks.mockedUsers)) {
      $$.mocks.mockLoginHistory('empty', undefined, [userId]);
    }

    // Act
    const repo = new Users($$.targetOrgConnection);
    const users = await repo.resolve({ withLoginHistory: true });

    // Assert
    expect(users.size).to.equal(3);
    for (const user of users.values()) {
      // explicitly mocked results for each user id was "empty"
      // the initial mock for all users is not used
      expect(user.logins).to.deep.equal([]);
    }
  });
});
