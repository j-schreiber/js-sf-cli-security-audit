import fs from 'node:fs';
import path from 'node:path';
import { assert, expect } from 'chai';
import { Messages } from '@salesforce/core';
import OrgAuditInit from '../../../../src/commands/org/audit/init.js';
import AuditTestContext from '../../../mocks/auditTestContext.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);

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
    // exact number of "Permissions*" field in test describe result
    const expectedPermsCount = 417;
    expect(result.policies.userPermissions.length).to.equal(expectedPermsCount);
    expect($$.sfCommandStubs.log.args.flat()).to.deep.equal([]);
    expect($$.sfCommandStubs.logSuccess.args.flat()).to.deep.equal([
      `Initialised policy with ${expectedPermsCount} permissions at policies/permissions/userPermissions.yml`,
    ]);
    expect(fs.existsSync(path.join('policies', 'permissions', 'userPermissions.yml'))).to.equal(true);
  });
});
