import fs from 'node:fs';
import path from 'node:path';
import { assert, expect } from 'chai';
import { Messages } from '@salesforce/core';
import OrgAuditInit, { OrgAuditInitResult } from '../../../../src/commands/org/audit/init.js';
import AuditTestContext from '../../../mocks/auditTestContext.js';
import { CUSTOM_PERMS_QUERY, PROFILES_QUERY } from '../../../../src/libs/config/queries.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);

const DEFAULT_USER_PERMS_PATH = path.join('my-test-org', 'classification', 'userPermissions.yml');
const DEFAULT_CUSTOM_PERMS_PATH = path.join('my-test-org', 'classification', 'customPermissions.yml');
const DEFAULT_PROFILES_PATH = path.join('my-test-org', 'policies', 'profiles.yml');
// const DEFAULT_PERMSETS_PATH = path.join('my-test-org', 'policies', 'permissionSets.yml');

describe('org audit init', () => {
  const $$ = new AuditTestContext();

  beforeEach(async () => {
    await $$.init();
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
    assert.isDefined(result.classifications.userPermissions);
    assert.isDefined(result.classifications.customPermissions);
    const expectedPermsCount = 417;
    const expectedCustomPerms = 3;
    expect(getUserPermsCount(result)).to.equal(expectedPermsCount);
    expect(getCustomPermsCount(result)).to.equal(expectedCustomPerms);
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
    assert.isDefined(result.classifications.userPermissions);
    assert.isDefined(result.classifications.customPermissions);
    const expectedPermsCount = 417;
    const expectedCustomPerms = 0;
    expect(getCustomPermsCount(result)).to.equal(expectedCustomPerms);
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
    expect(result.policies.profiles.content.enabled).to.be.true;
    const profiles = result.policies.profiles.content.profiles;
    const expectedProfiles = 21;
    expect(Object.keys(profiles).length).to.equal(expectedProfiles);
    expect(fs.existsSync(DEFAULT_PROFILES_PATH)).to.be.true;
    // expect($$.sfCommandStubs.logSuccess.args.flat()).to.deep.equal([
    //   `Initialised policy with ${expectedProfiles} profiles at ${DEFAULT_PROFILES_PATH}.`,
    // ]);
  });
});

function getUserPermsCount(result: OrgAuditInitResult): number | undefined {
  return result.classifications.userPermissions
    ? Object.entries(result.classifications.userPermissions.content.permissions).length
    : undefined;
}

function getCustomPermsCount(result: OrgAuditInitResult): number | undefined {
  return result.classifications.customPermissions
    ? Object.entries(result.classifications.customPermissions.content.permissions).length
    : undefined;
}
