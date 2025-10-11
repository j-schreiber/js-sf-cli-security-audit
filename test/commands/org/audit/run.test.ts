import fs from 'node:fs';
import path from 'node:path';
import { expect } from 'chai';
import { Messages } from '@salesforce/core';
import OrgAuditRun from '../../../../src/commands/org/audit/run.js';
import AuditTestContext from '../../../mocks/auditTestContext.js';
import AuditRun from '../../../../src/libs/policies/auditRun.js';
import { AuditResult } from '../../../../src/libs/audit/types.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'org.audit.run');

const DEFAULT_DATA_PATH = path.join('test', 'mocks', 'data', 'audit-lib-results', 'run');

const FULL_AUDIT_INIT_RESULT = parseMockAuditConfig('full-non-compliant.json');

function parseMockAuditConfig(filePath: string): AuditResult {
  return JSON.parse(fs.readFileSync(path.join(DEFAULT_DATA_PATH, filePath), 'utf-8')) as AuditResult;
}

describe('org audit run', () => {
  const $$ = new AuditTestContext();

  beforeEach(async () => {
    await $$.init();
  });

  afterEach(async () => {
    $$.reset();
  });

  it('reports summary of all executed policies and their status for non-compliant result', async () => {
    // Arrange
    const initMock = $$.context.SANDBOX.stub(AuditRun.prototype, 'execute').resolves(FULL_AUDIT_INIT_RESULT);

    // Act
    const result = await OrgAuditRun.run([
      '--target-org',
      $$.targetOrg.username,
      '--source-dir',
      'test/mocks/data/audit-configs/full-valid',
    ]);

    // Assert
    // ensure contract - all relevant params are actually passed to lib
    expect(initMock.callCount).to.equal(1);
    const conParam = initMock.args.flat()[0];
    expect(conParam.getUsername()).to.equal($$.targetOrg.username);

    // lib result is passed through as command result
    expect(result).to.deep.equal(FULL_AUDIT_INIT_RESULT);

    // all relevant audit result infos are formatted to stdout
    const executedPolicies = Object.entries(FULL_AUDIT_INIT_RESULT.policies).length;
    expect($$.sfCommandStubs.log.args.flat()).to.deep.equal([
      messages.getMessage('success.summary', [executedPolicies]),
      '',
    ]);
    expect($$.sfCommandStubs.table.callCount).to.equal(5);
    expect($$.sfCommandStubs.table.args.flat()[0]).to.deep.contain({
      data: [
        { policy: 'Profiles', isCompliant: false, rulesExecuted: 2, auditedEntities: 3 },
        { policy: 'PermissionSets', isCompliant: false, rulesExecuted: 1, auditedEntities: 3 },
      ],
    });
    expect($$.sfCommandStubs.table.args.flat()[1]).to.deep.contain({
      data: [
        { rule: 'EnforceClassificationPresets', isCompliant: false, violations: 3, errors: 0, warnings: 2 },
        { rule: 'SingleAdminProfileInUse', isCompliant: true, violations: 0, errors: 0, warnings: 0 },
      ],
    });
    expect($$.sfCommandStubs.table.args.flat()[2]).to.deep.contain({
      data: [
        {
          identifier: ['Standard User', 'ViewSetup'],
          message: 'Permission is classified as High but profile uses preset Standard User',
        },
        {
          identifier: ['Custom Standard User', 'ViewSetup'],
          message: 'Permission is classified as High but profile uses preset Standard User',
        },
        {
          identifier: ['System Administrator', 'AuthorApex'],
          message: 'Permission is classified as Critical but profile uses preset Admin',
        },
      ],
    });
  });
});
