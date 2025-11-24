import { expect } from 'chai';
import AuditTestContext from '../mocks/auditTestContext.js';
import UsersRepository from '../../src/libs/core/mdapi/usersRepository.js';

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
    expect(users.has('test-user-1@example.de')).to.be.true;
    expect(users.has('test-user-2@example.de')).to.be.true;
    for (const user of users.values()) {
      expect(user.logins).not.to.be.undefined;
    }
  });
});
