import fs from 'node:fs';
import path from 'node:path';
import { expect } from 'chai';
import { StandardColors } from '@salesforce/sf-plugins-core';
import { Messages } from '@salesforce/core';
import OrgAuditRun from '../../../../src/commands/org/audit/run.js';
import AuditTestContext, { clearAuditReports } from '../../../mocks/auditTestContext.js';
import AuditRun from '../../../../src/libs/policies/auditRun.js';
import { AuditResult } from '../../../../src/libs/audit/types.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'org.audit.run');

const DEFAULT_DATA_PATH = path.join('test', 'mocks', 'data', 'audit-lib-results', 'run');
const DEFAULT_WORKING_DIR = path.join('test', 'mocks', 'data', 'audit-configs', 'full-valid');

const NON_COMPLIANT_RESULT = parseMockAuditConfig('full-non-compliant.json');

function parseMockAuditConfig(filePath: string): AuditResult {
  return readAuditResultFromFile(path.join(DEFAULT_DATA_PATH, filePath));
}

function readAuditResultFromFile(fullFilePath: string): AuditResult {
  return JSON.parse(fs.readFileSync(fullFilePath, 'utf-8')) as AuditResult;
}

describe('org audit run', () => {
  const $$ = new AuditTestContext();

  function mockResult(result: AuditResult) {
    return $$.context.SANDBOX.stub(AuditRun.prototype, 'execute').resolves(result);
  }

  beforeEach(async () => {
    await $$.init();
  });

  afterEach(async () => {
    $$.reset();
    clearAuditReports(DEFAULT_WORKING_DIR);
  });

  it('reports summary of all executed policies and their status for non-compliant result', async () => {
    // Arrange
    const initMock = mockResult(NON_COMPLIANT_RESULT);

    // Act
    const result = await OrgAuditRun.run(['--target-org', $$.targetOrg.username, '--source-dir', DEFAULT_WORKING_DIR]);

    // Assert
    // ensure contract - all relevant params are actually passed to lib
    expect(initMock.callCount).to.equal(1);
    const conParam = initMock.args.flat()[0];
    expect(conParam.getUsername()).to.equal($$.targetOrg.username);

    // lib result is passed through as command result
    expect(result).to.deep.contain(NON_COMPLIANT_RESULT);

    // all relevant audit result infos are formatted to stdout
    const executedPolicies = Object.entries(NON_COMPLIANT_RESULT.policies).length;
    expect($$.sfCommandStubs.log.args.flat()).to.deep.equal([
      messages.getMessage('success.summary', [executedPolicies]),
      StandardColors.error(messages.getMessage('summary-non-compliant')),
      '',
    ]);
    expect($$.sfCommandStubs.table.callCount).to.equal(5);
    expect($$.sfCommandStubs.table.args.flat()[0]).to.deep.contain({
      data: [
        { policy: 'Profiles', isCompliant: false, rulesExecuted: 2, auditedEntities: 3, ignoredEntities: 1 },
        { policy: 'PermissionSets', isCompliant: false, rulesExecuted: 1, auditedEntities: 3, ignoredEntities: 0 },
      ],
    });
    expect($$.sfCommandStubs.table.args.flat()[1]).to.deep.contain({
      data: [
        { rule: 'EnforceUserPermissionClassifications', isCompliant: false, violations: 3, errors: 0, warnings: 2 },
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

  it('writes audit result to source directory', async () => {
    // Arrange
    mockResult(NON_COMPLIANT_RESULT);

    // Act
    const result = await OrgAuditRun.run(['--target-org', $$.targetOrg.username, '--source-dir', DEFAULT_WORKING_DIR]);

    // Assert
    expect(fs.existsSync(result.filePath)).to.be.true;
    expect($$.sfCommandStubs.info.args.flat()).to.deep.equal([
      messages.getMessage('info.report-file-location', [result.filePath]),
    ]);
    expect(result.orgId).to.equal($$.targetOrg.orgId);
    const expectedFullPath = path.join(DEFAULT_WORKING_DIR, `report_${$$.targetOrg.orgId}`);
    // we assert that the path "starts with" expected path - but no date mocking
    expect(result.filePath).to.contain(expectedFullPath);
    const fileContent = readAuditResultFromFile(result.filePath);
    expect(fileContent).to.deep.contain(NON_COMPLIANT_RESULT);
  });
});
