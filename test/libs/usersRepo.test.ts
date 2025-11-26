import path from 'node:path';
import { expect, assert } from 'chai';
import { PermissionSet } from '@jsforce/jsforce-node/lib/api/metadata.js';
import AuditTestContext, { parseProfileFromFile, RETRIEVES_BASE } from '../mocks/auditTestContext.js';
import UsersRepository, { User } from '../../src/libs/core/mdapi/usersRepository.js';
import { buildPermsetAssignmentsQuery } from '../../src/libs/core/constants.js';
import { NamedTypesRegistry } from '../../src/libs/core/mdapi/mdapiRetriever.js';

function parsePermSet(permSetName: string): PermissionSet {
  const permsetPath = path.join(RETRIEVES_BASE, 'full-permsets', `${permSetName}.permissionset-meta.xml`);
  return NamedTypesRegistry.PermissionSet.parse(permsetPath);
}

describe('users repository', () => {
  const $$ = new AuditTestContext();

  beforeEach(async () => {
    await $$.init();
  });

  afterEach(async () => {
    $$.reset();
  });

  it('resolves all users that exist on the org with default opts to a map', async () => {
    // Act
    const repo = new UsersRepository($$.targetOrgConnection);
    const users = await repo.resolveAllUsers();

    // Assert
    expect(users.size).to.equal(3);
    expect(users.has('test-user-1@example.de')).to.be.true;
    expect(users.has('test-user-2@example.de')).to.be.true;
    for (const user of users.values()) {
      expect(user.logins).to.be.undefined;
    }
  });

  it('resolves all users that exist on the org with login history to a map', async () => {
    // Act
    const repo = new UsersRepository($$.targetOrgConnection);
    const users = await repo.resolveAllUsers({ withLoginHistory: true, loginHistoryDaysToAnalyse: 14 });

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
    });
    expect(users.has('test-user-2@example.de')).to.be.true;
    for (const user of users.values()) {
      expect(user.logins).not.to.be.undefined;
    }
  });

  it('resolves assigned permission sets to existing users from target org', async () => {
    // Arrange
    // test-user-2@example.de
    $$.mocks.setQueryMock(buildPermsetAssignmentsQuery(['0054P00000AaGueQAF']), 'test-user-assignments');

    // Act
    const repo = new UsersRepository($$.targetOrgConnection);
    const userPerms = await repo.resolvePermissionSetAssignments(['0054P00000AaGueQAF']);

    // Assert
    expect(userPerms.size).to.equal(1);
    const perms = userPerms.get('0054P00000AaGueQAF');
    assert.isDefined(perms);
    expect(perms.length).to.equal(2);
    expect(perms[0]).to.deep.contain({
      permissionSetIdentifier: 'Test_Admin_Permission_Set_1',
      permissionSetSource: 'direct',
      metadata: parsePermSet('Test_Admin_Permission_Set_1'),
    });
  });

  it('resolves empty list if user has no assignments', async () => {
    // Arrange
    // test-user-2@example.de
    $$.mocks.setQueryMock(buildPermsetAssignmentsQuery(['0054P00000AaGueQAF']), 'empty');

    // Act
    const repo = new UsersRepository($$.targetOrgConnection);
    const userPerms = await repo.resolvePermissionSetAssignments(['0054P00000AaGueQAF']);

    // Assert
    expect(userPerms.size).to.equal(1);
    const perms = userPerms.get('0054P00000AaGueQAF');
    assert.isDefined(perms);
    expect(perms).to.deep.equal([]);
  });

  it('resolves full user permissions for existing user on target org', async () => {
    // Arrange
    $$.mocks.setQueryMock(buildPermsetAssignmentsQuery(['0054P00000AaGueQAF']), 'test-user-assignments');

    // Act
    const repo = new UsersRepository($$.targetOrgConnection);
    const userPerms = await repo.resolveUserPermissions([
      { profileName: 'System Administrator', userId: '0054P00000AaGueQAF' } as User,
    ]);

    // Assert
    expect(userPerms.size).to.equal(1);
    const perms = userPerms.get('0054P00000AaGueQAF');
    assert.isDefined(perms);
    expect(perms.assignedPermissionsets.length).to.equal(2);
    const expectedProfile = parseProfileFromFile('admin-profile-with-metadata');
    // mdapi retriever also applies post processor to clean missing properties
    // .deep.contain matches "good enough" without the need to replicate post processing
    expect(perms.profileMetadata).to.deep.contain(expectedProfile);
  });
});
