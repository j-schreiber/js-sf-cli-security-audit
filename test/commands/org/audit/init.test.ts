import fs from 'node:fs';
import path from 'node:path';
import { expect } from 'chai';
import { Connection, Messages } from '@salesforce/core';
import OrgAuditInit from '../../../../src/commands/org/audit/init.js';
import AuditTestContext from '../../../mocks/auditTestContext.js';
import AuditRun from '../../../../src/libs/policies/auditRun.js';
import AuditRunConfig from '../../../../src/libs/policies/interfaces/auditRunConfig.js';
import { PermissionSetLikeMap } from '../../../../src/libs/policies/schema.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);

const DEFAULT_DATA_PATH = path.join('test', 'mocks', 'data', 'audit-lib-results', 'init');

const FULL_AUDIT_INIT_RESULT = parseMockAuditConfig('full.json');
const MINIMAL_AUDIT_INIT_RESULT = parseMockAuditConfig('minimal.json');

function parseMockAuditConfig(filePath: string): AuditRunConfig {
  const rawResult = JSON.parse(fs.readFileSync(path.join(DEFAULT_DATA_PATH, filePath), 'utf-8')) as AuditRunConfig;
  if (rawResult.policies.Profiles) {
    rawResult.policies.Profiles.getValues = () => rawResult.policies.Profiles?.content.profiles as PermissionSetLikeMap;
  }
  if (rawResult.policies.PermissionSets) {
    rawResult.policies.PermissionSets.getValues = () =>
      rawResult.policies.PermissionSets?.content.permissionSets as PermissionSetLikeMap;
  }
  return rawResult;
}

describe('org audit init', () => {
  const $$ = new AuditTestContext();

  beforeEach(async () => {
    await $$.init();
  });

  afterEach(async () => {
    $$.reset();
  });

  it('reports created files and statistics for full initialisation', async () => {
    // Arrange
    const initMock = $$.context.SANDBOX.stub(AuditRun, 'initialiseNewConfig').resolves(FULL_AUDIT_INIT_RESULT);

    // Act
    const result = await OrgAuditInit.run(['--target-org', $$.targetOrg.username, '--output-dir', 'my-test-org']);

    // Assert
    // ensure contract - all relevant params are actually passed to lib
    expect(initMock.callCount).to.equal(1);
    const conParam = initMock.args.flat()[0] as Connection;
    const optsParam = initMock.args.flat()[1];
    expect(conParam.getUsername()).to.equal($$.targetOrg.username);
    expect(optsParam).to.deep.equal({ directoryPath: 'my-test-org' });
    // command result accurately represents the lib result
    expect(result).to.deep.equal(FULL_AUDIT_INIT_RESULT);
    // relevant summary is printed to terminal
    expect($$.sfCommandStubs.logSuccess.args.flat()).to.deep.equal([
      'Initialised 3 permissions at tmp/prod/classification/userPermissions.yml.',
      'Initialised 1 permissions at tmp/prod/classification/customPermissions.yml.',
      'Initialised policy "Profiles" with 3 entities at tmp/prod/policies/profiles.yml.',
      'Initialised policy "PermissionSets" with 2 entities at tmp/prod/policies/permissionSets.yml.',
    ]);
  });

  it('reports created files and statistics for partial initialisation', async () => {
    // Arrange
    $$.context.SANDBOX.stub(AuditRun, 'initialiseNewConfig').resolves(MINIMAL_AUDIT_INIT_RESULT);

    // Act
    const result = await OrgAuditInit.run(['--target-org', $$.targetOrg.username, '--output-dir', 'my-test-org']);

    // Assert
    expect(result).to.deep.equal(MINIMAL_AUDIT_INIT_RESULT);
    expect($$.sfCommandStubs.logSuccess.args.flat()).to.deep.equal([
      'Initialised 3 permissions at tmp/prod/classification/userPermissions.yml.',
      'Initialised policy "Profiles" with 3 entities at tmp/prod/policies/profiles.yml.',
    ]);
  });
});
