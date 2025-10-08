import fs from 'node:fs';
import path from 'node:path';
import { assert, expect } from 'chai';
import { Messages } from '@salesforce/core';
import OrgAuditInit from '../../../../src/commands/org/audit/init.js';
import AuditTestContext from '../../../mocks/auditTestContext.js';
import { CUSTOM_PERMS_QUERY, PROFILES_QUERY } from '../../../../src/libs/policies/policies.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);

const DEFAULT_USER_PERMS_PATH = path.join('my-test-org', 'classification', 'userPermissions.yml');
const DEFAULT_CUSTOM_PERMS_PATH = path.join('my-test-org', 'classification', 'customPermissions.yml');
const DEFAULT_PROFILES_PATH = path.join('my-test-org', 'policies', 'profiles.yml');
// const DEFAULT_PERMSETS_PATH = path.join('my-test-org', 'policies', 'permissionSets.yml');

describe('org audit init', () => {
  const $$ = new AuditTestContext();

  beforeEach(async () => {
    $$.init();
  });

  afterEach(async () => {
    $$.reset();
  });

  it('initialises full permission classification from a target org', async () => {
    // Arrange
    $$.mocks.queries[PROFILES_QUERY] = [];

    // Act
    const result = await OrgAuditInit.run(['--target-org', $$.targetOrg.username, '--output-dir', 'my-test-org']);

    // Assert
    assert.isDefined(result.classification.userPermissions);
    assert.isDefined(result.classification.customPermissions);
    const expectedPermsCount = 417;
    const expectedCustomPerms = 3;
    expect(result.classification.userPermissions.length).to.equal(expectedPermsCount);
    expect(result.classification.customPermissions.length).to.equal(expectedCustomPerms);
    expect($$.sfCommandStubs.log.args.flat()).to.deep.equal([]);
    expect($$.sfCommandStubs.logSuccess.args.flat()).to.deep.equal([
      `Initialised ${expectedPermsCount} permissions at ${DEFAULT_USER_PERMS_PATH}.`,
      `Initialised ${expectedCustomPerms} permissions at ${DEFAULT_CUSTOM_PERMS_PATH}.`,
    ]);
    expect(fs.existsSync(DEFAULT_USER_PERMS_PATH)).to.equal(true);
    expect(fs.existsSync(DEFAULT_CUSTOM_PERMS_PATH)).to.equal(true);
  });

  it('initialises no custom permissions classification if org does not have any', async () => {
    // Arrange
    $$.mocks.queries[CUSTOM_PERMS_QUERY] = [];
    $$.mocks.queries[PROFILES_QUERY] = [];

    // Act
    const result = await OrgAuditInit.run(['--target-org', $$.targetOrg.username, '--output-dir', 'my-test-org']);

    // Assert
    assert.isDefined(result.classification.userPermissions);
    assert.isDefined(result.classification.customPermissions);
    const expectedPermsCount = 417;
    const expectedCustomPerms = 0;
    expect(result.classification.customPermissions.length).to.equal(expectedCustomPerms);
    expect($$.sfCommandStubs.log.args.flat()).to.deep.equal([]);
    expect($$.sfCommandStubs.logSuccess.args.flat()).to.deep.equal([
      `Initialised ${expectedPermsCount} permissions at ${DEFAULT_USER_PERMS_PATH}.`,
    ]);
    expect(fs.existsSync(DEFAULT_USER_PERMS_PATH)).to.equal(true);
    expect(fs.existsSync(DEFAULT_CUSTOM_PERMS_PATH)).to.equal(false);
  });

  it('initialises profile policy with profiles from a target org', async () => {
    // Arrange
    $$.mocks.queries[CUSTOM_PERMS_QUERY] = [];
    $$.mocks.describes['PermissionSet'] = { fields: [] };

    // Act
    const result = await OrgAuditInit.run(['--target-org', $$.targetOrg.username, '--output-dir', 'my-test-org']);

    // Assert
    assert.isDefined(result.policies.profiles);
    assert.isDefined(result.policies.profiles.profiles);
    expect(result.policies.profiles.enabled).to.be.true;
    const profiles = result.policies.profiles.profiles;
    const expectedProfiles = 21;
    expect(Object.keys(profiles).length).to.equal(expectedProfiles);
    expect(fs.existsSync(DEFAULT_PROFILES_PATH)).to.be.true;
    expect($$.sfCommandStubs.logSuccess.args.flat()).to.deep.equal([
      `Initialised policy with ${expectedProfiles} profiles at ${DEFAULT_PROFILES_PATH}.`,
    ]);
  });
});
