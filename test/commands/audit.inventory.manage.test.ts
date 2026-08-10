import fs from 'node:fs';
import path from 'node:path';
import { expect } from 'chai';
import { SinonStub } from 'sinon';
import { Messages } from '@salesforce/core';
import ManageInventory from '../../src/commands/audit/inventory/manage.js';
import AuditTestContext from '../mocks/auditTestContext.js';
import { loadAuditConfig } from '../../src/libs/audit-engine/index.js';
import Prompts from '../../src/ux/prompts.js';
import { AUDIT_CONFIGS_BASE } from '../mocks/data/paths.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'audit.inventory.manage');

const VALID_CONFIG_PATH = path.join(AUDIT_CONFIGS_BASE, 'minimal');
const WORKING_DIR = path.join('tmp', `inventory-manage-${Date.now()}`);

describe('audit inventory manage', () => {
  const $$ = new AuditTestContext();

  let selectStub: SinonStub;

  beforeEach(async () => {
    await $$.init();
    fs.cpSync(VALID_CONFIG_PATH, WORKING_DIR, { recursive: true });
    selectStub = $$.context.SANDBOX.stub(Prompts, 'select');
  });

  afterEach(async () => {
    $$.reset();
    fs.rmSync(WORKING_DIR, { force: true, recursive: true });
  });

  it('calls inventory-manager with command-line input and summarizes results', async () => {
    // Arrange
    // first prompt selects the inventory type, second selects the operation
    selectStub.onFirstCall().resolves('users');
    selectStub.onSecondCall().resolves('refresh');

    // Act
    const result = await ManageInventory.run(['--target-org', $$.targetOrg.username, '--source-dir', WORKING_DIR]);

    // Assert
    const newUsersFromMocks = ['guest-user@example.de', 'test-user-1@example.de', 'test-user-2@example.de'];
    expect(result).to.deep.contain({
      type: 'users',
      addedEntities: newUsersFromMocks,
      removedEntities: [],
    });
    const expectedMsg = messages.getMessage('ux.summary.completion', [3, 0, 'Users']);
    expect($$.sfCommandStubs.logSuccess.args.flat()).to.deep.equal([expectedMsg]);
    const reloadedConfig = loadAuditConfig(WORKING_DIR);
    expect(reloadedConfig.inventory.users).to.have.all.keys(newUsersFromMocks);
  });
});
