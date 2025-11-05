/* eslint-disable camelcase */
import { expect } from 'chai';
import { Messages } from '@salesforce/core';
import AuditTestContext from '../../mocks/auditTestContext.js';
import { UsersPolicyFileContent } from '../../../src/libs/core/file-mgmt/schema.js';
import UserPolicy from '../../../src/libs/policies/userPolicy.js';
import { buildPermsetAssignmentsQuery } from '../../../src/libs/core/constants.js';
import { ProfilesRiskPreset } from '../../../src/libs/core/policy-types.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);

const DEFAULT_CONFIG = {
  enabled: true,
  rules: {},
  options: {
    defaultRoleForMissingUsers: 'Standard User',
  },
  users: {
    'guest-user@example.de': {
      role: 'Standard User',
    },
    'test-user-2@example.de': {
      role: 'Admin',
    },
  },
} as UsersPolicyFileContent;

describe('users policy', () => {
  const $$ = new AuditTestContext();

  beforeEach(async () => {
    await $$.init();
  });

  afterEach(async () => {
    $$.reset();
  });

  it('resolves all users from config with active users on org', async () => {
    // Act
    const pol = new UserPolicy(DEFAULT_CONFIG, $$.mockAuditConfig);
    const resolveResult = await pol.resolve({ targetOrgConnection: await $$.targetOrg.getConnection() });

    // Assert
    expect(resolveResult.ignoredEntities).to.deep.equal([]);
    expect(Object.keys(resolveResult.resolvedEntities)).to.deep.equal([
      'guest-user@example.de',
      'test-user-1@example.de',
      'test-user-2@example.de',
    ]);
    expect(resolveResult.resolvedEntities['guest-user@example.de'].role).to.equal('Standard User');
    expect(resolveResult.resolvedEntities['guest-user@example.de'].assignedProfile).to.equal('Guest User Profile');
    expect(resolveResult.resolvedEntities['test-user-1@example.de'].role).to.equal('Standard User');
    expect(resolveResult.resolvedEntities['test-user-1@example.de'].assignedProfile).to.equal('Standard User Profile');
    expect(resolveResult.resolvedEntities['test-user-2@example.de'].role).to.equal('Admin');
    expect(resolveResult.resolvedEntities['test-user-2@example.de'].assignedProfile).to.equal('System Administrator');
  });

  it('ignores users with UNKNOWN role in resolve', async () => {
    // Arrange
    $$.mocks.setQueryMock(
      buildPermsetAssignmentsQuery(['005Pl000001p3HqIAI', '0054P00000AaGueQAF']),
      'test-user-assignments'
    );
    const config = structuredClone(DEFAULT_CONFIG);
    config.users['guest-user@example.de'].role = ProfilesRiskPreset.UNKNOWN;

    // Act
    const pol = new UserPolicy(config, $$.mockAuditConfig);
    const resolveResult = await pol.resolve({ targetOrgConnection: await $$.targetOrg.getConnection() });

    // Assert
    expect(resolveResult.ignoredEntities.length).to.equal(1);
    expect(resolveResult.ignoredEntities[0]).to.deep.contain({ name: 'guest-user@example.de' });
    expect(Object.keys(resolveResult.resolvedEntities)).to.deep.equal([
      'test-user-1@example.de',
      'test-user-2@example.de',
    ]);
  });
});
