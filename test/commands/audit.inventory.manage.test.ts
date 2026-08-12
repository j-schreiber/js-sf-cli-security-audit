import fs from 'node:fs';
import path from 'node:path';
import { expect } from 'chai';
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

  beforeEach(async () => {
    await $$.init();
    fs.cpSync(VALID_CONFIG_PATH, WORKING_DIR, { recursive: true });
  });

  afterEach(async () => {
    $$.reset();
    fs.rmSync(WORKING_DIR, { force: true, recursive: true });
  });

  it('calls inventory-manager with command-line input and summarizes results', async () => {
    // Arrange
    $$.context.SANDBOX.stub(Prompts, 'select').resolves('users');
    $$.context.SANDBOX.stub(Prompts, 'checkbox').resolves(['refresh']);

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

  it('prints manage result details to table when --verbose is set', async () => {
    // Arrange
    $$.context.SANDBOX.stub(Prompts, 'select').resolves('profiles');
    $$.context.SANDBOX.stub(Prompts, 'checkbox').resolves(['prune']);

    // Act
    const result = await ManageInventory.run([
      '--target-org',
      $$.targetOrg.username,
      '--source-dir',
      WORKING_DIR,
      '--verbose',
    ]);

    // Assert
    const removedProfiles = ['Guest License User', 'Minimum Access - Salesforce'];
    expect(result).to.deep.contain({
      type: 'profiles',
      addedEntities: [],
      removedEntities: removedProfiles,
    });
    expect($$.sfCommandStubs.logSuccess.args.flat()).to.deep.equal([
      messages.getMessage('ux.summary.completion', [0, 2, 'Profiles']),
    ]);
    const reloadedConfig = loadAuditConfig(WORKING_DIR);
    expect(reloadedConfig.inventory.profiles).to.have.all.keys(['System Administrator', 'Standard User']);
    expect($$.sfCommandStubs.table.args.flat()).to.deep.equal([
      { data: [{ removedProfiles: 'Guest License User' }, { removedProfiles: 'Minimum Access - Salesforce' }] },
    ]);
  });

  it('performs prune and refresh if both options are checked', async () => {
    // Arrange
    $$.context.SANDBOX.stub(Prompts, 'select').resolves('profiles');
    $$.context.SANDBOX.stub(Prompts, 'checkbox').resolves(['refresh', 'prune']);

    // Act
    const result = await ManageInventory.run(['--target-org', $$.targetOrg.username, '--source-dir', WORKING_DIR]);

    // Assert
    expect(result).to.deep.contain({
      type: 'profiles',
      addedEntities: ['Custom Profile'],
      removedEntities: ['Guest License User', 'Minimum Access - Salesforce'],
    });
  });

  it('second subsequent call with same configs is idempotent', async () => {
    // Arrange
    $$.context.SANDBOX.stub(Prompts, 'select').resolves('profiles');
    $$.context.SANDBOX.stub(Prompts, 'checkbox').resolves(['refresh', 'prune']);

    // Act
    await ManageInventory.run(['--target-org', $$.targetOrg.username, '--source-dir', WORKING_DIR]);
    const secondResult = await ManageInventory.run([
      '--target-org',
      $$.targetOrg.username,
      '--source-dir',
      WORKING_DIR,
    ]);

    // Assert
    expect(secondResult).to.deep.contain({
      type: 'profiles',
      addedEntities: [],
      removedEntities: [],
    });
  });
});
