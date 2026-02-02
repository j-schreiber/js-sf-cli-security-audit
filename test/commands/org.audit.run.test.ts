import fs from 'node:fs';
import path from 'node:path';
import { expect } from 'chai';
import { StandardColors } from '@salesforce/sf-plugins-core';
import { Messages } from '@salesforce/core';
import OrgAuditRun, { MERGE_CHAR } from '../../src/commands/org/audit/run.js';
import AuditTestContext, { clearAuditReports } from '../mocks/auditTestContext.js';
import { AuditResult, AuditRun } from '../../src/libs/audit-engine/index.js';
import { assertSfError } from '../mocks/testHelpers.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'org.audit.run');

const DEFAULT_DATA_PATH = path.join('test', 'mocks', 'data', 'audit-lib-results', 'run');
const AUDIT_CONFIGS_DIR = path.join('test', 'mocks', 'data', 'audit-configs');
const DEFAULT_WORKING_DIR = path.join(AUDIT_CONFIGS_DIR, 'full-valid');

const NON_COMPLIANT_RESULT = parseMockAuditConfig('full-non-compliant.json');
const COMPLIANT_RESULT = parseMockAuditConfig('full-compliant.json');
const PLAIN_IDENTIFIERS_RESULT = parseMockAuditConfig('plain-string-identifiers.json');
const EMPTY_RESULT = parseMockAuditConfig('empty-policy-no-rules.json');

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

  describe('exception handling', () => {
    it('aborts gracefully if root dir is empty', async () => {
      // Act
      try {
        await OrgAuditRun.run(['--target-org', $$.targetOrg.username]);
        expect.fail('Expected exception,but succeeded');
      } catch (error) {
        assertSfError(error, 'NoAuditConfigFound', 'The target directory <root-dir> is empty');
      }
    });

    it('aborts gracefully if supplied source dir is empty', async () => {
      // Act
      const sourceDirPath = path.join(AUDIT_CONFIGS_DIR, 'empty');
      try {
        await OrgAuditRun.run(['--target-org', $$.targetOrg.username, '--source-dir', sourceDirPath]);
        expect.fail('Expected exception,but succeeded');
      } catch (error) {
        assertSfError(error, 'NoAuditConfigFound', `The target directory ${sourceDirPath} is empty`);
      }
    });

    it('aborts gracefully if no classification was found for profiles', async () => {
      // Act
      try {
        await OrgAuditRun.run([
          '--target-org',
          $$.targetOrg.username,
          '--source-dir',
          path.join(AUDIT_CONFIGS_DIR, 'no-classifications'),
        ]);
        expect.fail('Expected exception,but succeeded');
      } catch (error) {
        assertSfError(error, 'UserPermClassificationRequiredForProfiles');
      }
    });

    it('aborts gracefully if no classification was found for permission sets', async () => {
      // Act
      try {
        await OrgAuditRun.run([
          '--target-org',
          $$.targetOrg.username,
          '--source-dir',
          path.join(AUDIT_CONFIGS_DIR, 'no-classifications-2'),
        ]);
        expect.fail('Expected exception,but succeeded');
      } catch (error) {
        assertSfError(error, 'UserPermClassificationRequiredForPermSets');
      }
    });
  });

  describe('audit result reporting', () => {
    it('reports summary of all executed policies and their status for non-compliant result', async () => {
      // Arrange
      const libMock = mockResult(NON_COMPLIANT_RESULT);

      // Act
      const result = await OrgAuditRun.run([
        '--target-org',
        $$.targetOrg.username,
        '--source-dir',
        DEFAULT_WORKING_DIR,
      ]);

      // Assert
      // ensure contract - all relevant params are actually passed to lib
      expect(libMock.callCount).to.equal(1);
      const conParam = libMock.args.flat()[0];
      expect(conParam.getUsername()).to.equal($$.targetOrg.username);

      // lib result is passed through as command result
      expect(result).to.deep.contain(NON_COMPLIANT_RESULT);

      // all relevant audit result infos are formatted to stdout
      expect($$.sfCommandStubs.log.args.flat()).to.deep.equal([
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
          {
            rule: 'EnforcePermissionClassifications',
            isCompliant: false,
            violations: 3,
            errors: 0,
            warnings: 2,
            compliantEntities: 0,
            violatedEntities: 3,
          },
          {
            rule: 'SingleAdminProfileInUse',
            isCompliant: true,
            violations: 0,
            errors: 0,
            warnings: 0,
            compliantEntities: 0,
            violatedEntities: 0,
          },
        ],
      });
      expect($$.sfCommandStubs.table.args.flat()[2]).to.deep.contain({
        data: [
          {
            identifier: ['Standard User', 'ViewSetup'].join(MERGE_CHAR),
            message: 'Permission is classified as High but profile uses preset Standard User',
          },
          {
            identifier: ['Custom Standard User', 'ViewSetup'].join(MERGE_CHAR),
            message: 'Permission is classified as High but profile uses preset Standard User',
          },
          {
            identifier: ['System Administrator', 'AuthorApex'].join(MERGE_CHAR),
            message: 'Permission is classified as Critical but profile uses preset Admin',
          },
        ],
      });
    });

    it('reports violations with plain string identifiers in data table', async () => {
      // Arrange
      mockResult(PLAIN_IDENTIFIERS_RESULT);

      // Act
      await OrgAuditRun.run(['--target-org', $$.targetOrg.username, '--source-dir', DEFAULT_WORKING_DIR]);

      // Arrange
      expect($$.sfCommandStubs.table.callCount).to.equal(3);
      expect($$.sfCommandStubs.table.args.flat()[1]).to.deep.contain({
        data: [
          {
            rule: 'MockRule',
            isCompliant: false,
            violations: 1,
            errors: 0,
            warnings: 0,
            compliantEntities: 3,
            violatedEntities: 0,
          },
        ],
      });
      expect($$.sfCommandStubs.table.args.flat()[2]).to.deep.contain({
        data: [
          {
            identifier: 'Plain_Text_Identifier',
            message: 'Error message',
          },
        ],
      });
    });

    it('does not report rule summary when policy had no executed rules', async () => {
      // Arrange
      mockResult(EMPTY_RESULT);

      // Act
      await OrgAuditRun.run(['--target-org', $$.targetOrg.username, '--source-dir', DEFAULT_WORKING_DIR]);

      // Assert
      // all relevant audit result infos are formatted to stdout
      expect($$.sfCommandStubs.logSuccess.args.flat()).to.deep.equal([
        messages.getMessage('success.all-policies-compliant'),
      ]);
      expect($$.sfCommandStubs.table.callCount).to.equal(1);
      expect($$.sfCommandStubs.table.args.flat()[0]).to.deep.contain({
        data: [{ policy: 'Profiles', isCompliant: true, rulesExecuted: 0, auditedEntities: 3, ignoredEntities: 1 }],
      });
    });

    it('does not report policies that were disabled', async () => {
      // Arrange
      const mr = structuredClone(COMPLIANT_RESULT);
      mr.policies.profiles!.enabled = false;
      mockResult(mr);

      // Act
      await OrgAuditRun.run(['--target-org', $$.targetOrg.username, '--source-dir', DEFAULT_WORKING_DIR]);

      // Assert
      // ensure contract - all relevant params are actually passed to lib
      expect($$.sfCommandStubs.table.callCount).to.equal(2);
      expect($$.sfCommandStubs.table.args.flat()[0]).to.deep.contain({
        data: [
          { policy: 'PermissionSets', isCompliant: true, rulesExecuted: 1, auditedEntities: 3, ignoredEntities: 0 },
        ],
      });
      expect($$.sfCommandStubs.table.args.flat()[1]).to.deep.contain({
        data: [
          {
            rule: 'EnforcePermissionClassifications',
            isCompliant: true,
            violations: 0,
            errors: 0,
            warnings: 2,
            compliantEntities: 3,
            violatedEntities: 0,
          },
        ],
      });
    });

    it('formats date-time in identifiers to current user locale', async () => {
      // Arrange
      const mr = parseMockAuditConfig('date-time-identifiers.json');
      mockResult(mr);

      // Act
      await OrgAuditRun.run(['--target-org', $$.targetOrg.username, '--source-dir', DEFAULT_WORKING_DIR]);

      // Assert
      expect($$.sfCommandStubs.table.callCount).to.equal(3);
      const expectedDateOutput = new Date(
        mr.policies.users!.executedRules.NoOtherApexApiLogins.violations[0].identifier[1]
      );
      // third call to .table() are the violations from rule
      expect($$.sfCommandStubs.table.args.flat()[2]).to.deep.contain({
        data: [
          {
            identifier: `business@jannis-schreiber.me${MERGE_CHAR}${expectedDateOutput.toLocaleString()}`,
            message: 'Violation message',
          },
        ],
      });
    });

    it('truncates violation tables to default max length without --verbose flag', async () => {
      // Arrange
      const mr = parseMockAuditConfig('large-violations-list.json');
      mockResult(mr);

      // Act
      await OrgAuditRun.run(['--target-org', $$.targetOrg.username, '--source-dir', DEFAULT_WORKING_DIR]);

      // Assert
      expect($$.sfCommandStubs.table.callCount).to.equal(3);
      const violationsTable = $$.sfCommandStubs.table.args.flat()[2];
      expect(violationsTable.data.length).to.equal(30);
      const expectedMsg = messages.getMessage('info.RemovedViolationRows', [30, 50]);
      expect($$.sfCommandStubs.info.args.flat()).to.deep.include.members([expectedMsg]);
    });

    it('does not truncate exceeding violations table with --verbose flag', async () => {
      // Arrange
      const mr = parseMockAuditConfig('large-violations-list.json');
      mockResult(mr);

      // Act
      await OrgAuditRun.run(['--target-org', $$.targetOrg.username, '--source-dir', DEFAULT_WORKING_DIR, '--verbose']);

      // Assert
      expect($$.sfCommandStubs.table.callCount).to.equal(3);
      const violationsTable = $$.sfCommandStubs.table.args.flat()[2];
      expect(violationsTable.data.length).to.equal(50);
      expect($$.sfCommandStubs.info.args.flat()).to.deep.include.members([]);
    });

    it('does not truncate violations table when max-length is increased', async () => {
      // Arrange
      process.env.SAE_MAX_RESULT_VIOLATION_ROWS = '100';
      const mr = parseMockAuditConfig('large-violations-list.json');
      mockResult(mr);

      // Act
      await OrgAuditRun.run(['--target-org', $$.targetOrg.username, '--source-dir', DEFAULT_WORKING_DIR, '--verbose']);

      // Assert
      expect($$.sfCommandStubs.table.callCount).to.equal(3);
      const violationsTable = $$.sfCommandStubs.table.args.flat()[2];
      expect(violationsTable.data.length).to.equal(50);
      expect($$.sfCommandStubs.info.args.flat()).to.deep.include.members([]);
    });
  });

  describe('report file creation', () => {
    it('writes audit result to source directory', async () => {
      // Arrange
      NON_COMPLIANT_RESULT.orgId = $$.targetOrg.orgId;
      mockResult(NON_COMPLIANT_RESULT);

      // Act
      const result = await OrgAuditRun.run([
        '--target-org',
        $$.targetOrg.username,
        '--source-dir',
        DEFAULT_WORKING_DIR,
      ]);

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
});
