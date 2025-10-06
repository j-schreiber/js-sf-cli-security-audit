import fs from 'node:fs';
import path from 'node:path';
import { assert, expect } from 'chai';
import { Messages } from '@salesforce/core';
import OrgAuditInit from '../../../../src/commands/org/audit/init.js';
import AuditTestContext from '../../../mocks/auditTestContext.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);

const DEFAULT_USER_PERMS_PATH = path.join('policies', 'permissions', 'userPermissions.yml');
const DEFAULT_CUSTOM_PERMS_PATH = path.join('policies', 'permissions', 'customPermissions.yml');

describe('org audit init', () => {
  const $$ = new AuditTestContext();

  beforeEach(async () => {
    $$.init();
  });

  afterEach(async () => {
    $$.reset();
  });

  it('initialises user permission policies from a target org in default directory', async () => {
    // Act
    const result = await OrgAuditInit.run(['--target-org', $$.targetOrg.username]);

    // Assert
    assert.isDefined(result.policies.userPermissions);
    assert.isDefined(result.policies.customPermissions);
    const expectedPermsCount = 417;
    const expectedCustomPerms = 3;
    expect(result.policies.userPermissions.length).to.equal(expectedPermsCount);
    expect(result.policies.customPermissions.length).to.equal(expectedCustomPerms);
    expect($$.sfCommandStubs.log.args.flat()).to.deep.equal([]);
    expect($$.sfCommandStubs.logSuccess.args.flat()).to.deep.equal([
      `Initialised ${expectedPermsCount} permissions at ${DEFAULT_USER_PERMS_PATH}`,
      `Initialised ${expectedCustomPerms} permissions at ${DEFAULT_CUSTOM_PERMS_PATH}`,
    ]);
    expect(fs.existsSync(DEFAULT_USER_PERMS_PATH)).to.equal(true);
    expect(fs.existsSync(DEFAULT_CUSTOM_PERMS_PATH)).to.equal(true);
  });

  it('initialises no custom permissions policy if org does not have any', async () => {
    // Arrange
    $$.mocks.queries['SELECT Id,MasterLabel,DeveloperName FROM CustomPermission'] = [];

    // Act
    const result = await OrgAuditInit.run(['--target-org', $$.targetOrg.username]);

    // Assert
    assert.isDefined(result.policies.userPermissions);
    assert.isDefined(result.policies.customPermissions);
    const expectedPermsCount = 417;
    const expectedCustomPerms = 0;
    expect(result.policies.customPermissions.length).to.equal(expectedCustomPerms);
    expect($$.sfCommandStubs.log.args.flat()).to.deep.equal([]);
    expect($$.sfCommandStubs.logSuccess.args.flat()).to.deep.equal([
      `Initialised ${expectedPermsCount} permissions at ${DEFAULT_USER_PERMS_PATH}`,
    ]);
    expect(fs.existsSync(DEFAULT_USER_PERMS_PATH)).to.equal(true);
    expect(fs.existsSync(DEFAULT_CUSTOM_PERMS_PATH)).to.equal(false);
  });
});
