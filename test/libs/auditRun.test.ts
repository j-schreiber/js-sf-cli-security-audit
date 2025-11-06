import fs from 'node:fs';
import path from 'node:path';
import { expect, assert } from 'chai';
import { Messages } from '@salesforce/core';
import AuditTestContext from '../mocks/auditTestContext.js';
import { startAuditRun } from '../../src/libs/core/auditRun.js';

const TEST_DIR_BASE_PATH = path.join('test', 'mocks', 'data', 'audit-configs');
// const QUERIES_BASE_PATH = path.join('test', 'mocks', 'data', 'queryResults');
const DEFAULT_TEST_OUTPUT_DIR = path.join(TEST_DIR_BASE_PATH, 'tmp-1');

function buildPath(dirName: string) {
  return path.join(TEST_DIR_BASE_PATH, dirName);
}

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const generalPolicyMessages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policies.general');

describe('audit run execution', () => {
  const $$ = new AuditTestContext();

  beforeEach(async () => {
    await $$.init();
  });

  afterEach(async () => {
    $$.reset();
    fs.rmSync(DEFAULT_TEST_OUTPUT_DIR, { recursive: true, force: true });
  });

  it('executes all loaded policies', async () => {
    // Arrange
    const dirPath = buildPath('full-valid');
    const audit = startAuditRun(dirPath);

    // Act
    const auditResult = await audit.execute(await $$.targetOrg.getConnection());

    // Assert
    expect(auditResult.isCompliant).to.be.true;
    assert.isDefined(auditResult.policies);
    assert.isDefined(auditResult.policies.Profiles);
    assert.isDefined(auditResult.policies.PermissionSets);
    assert.isDefined(auditResult.policies.Users);
    expect(auditResult.policies.Profiles.isCompliant).to.be.true;
    expect(auditResult.policies.PermissionSets.isCompliant).to.be.true;
    expect(Object.keys(auditResult.policies.Profiles.executedRules)).to.deep.equal([
      'EnforceUserPermissionClassifications',
    ]);
    expect(Object.keys(auditResult.policies.PermissionSets.executedRules)).to.deep.equal([
      'EnforceUserPermissionClassifications',
    ]);
  });

  it('reports non-compliance if one policy is not compliant', async () => {
    // Arrange
    const dirPath = buildPath('non-compliant');
    const audit = startAuditRun(dirPath);

    // Act
    const auditResult = await audit.execute(await $$.targetOrg.getConnection());

    // Assert
    expect(auditResult.isCompliant).to.be.false;
    assert.isDefined(auditResult.policies);
    assert.isDefined(auditResult.policies.Profiles);
    expect(auditResult.policies.Profiles.isCompliant).to.be.false;
    assert.isDefined(auditResult.policies.Profiles.executedRules.EnforceUserPermissionClassifications);
    expect(auditResult.policies.Profiles.executedRules.EnforceUserPermissionClassifications.isCompliant).to.be.false;
  });

  it('runs only enabled policies', async () => {
    // Arrange
    const dirPath = buildPath('full-valid');
    const audit = startAuditRun(dirPath);
    audit.configs.policies.Profiles!.content.enabled = false;

    // Act
    const auditResult = await audit.execute(await $$.targetOrg.getConnection());

    // Assert
    expect(auditResult.isCompliant).to.be.true;
    assert.isDefined(auditResult.policies);
    assert.isDefined(auditResult.policies.Profiles);
    expect(auditResult.policies.Profiles.enabled).to.equal(false);
    expect(auditResult.policies.Profiles.executedRules).to.deep.equal({});
  });

  it('runs only enabled rules on policy', async () => {
    // Arrange
    const dirPath = buildPath('full-valid');
    const audit = startAuditRun(dirPath);
    audit.configs.policies.ConnectedApps!.content.rules.AllUsedAppsUnderManagement.enabled = false;

    // Act
    const auditResult = await audit.execute(await $$.targetOrg.getConnection());

    // Assert
    expect(auditResult.isCompliant).to.be.true;
    assert.isDefined(auditResult.policies);
    assert.isDefined(auditResult.policies.ConnectedApps);
    expect(auditResult.policies.ConnectedApps.enabled).to.equal(true);
    expect(Object.keys(auditResult.policies.ConnectedApps.executedRules)).to.deep.equal(['NoUserCanSelfAuthorize']);
    expect(auditResult.policies.ConnectedApps.skippedRules).to.deep.equal([
      {
        name: 'AllUsedAppsUnderManagement',
        skipReason: generalPolicyMessages.getMessage('skip-reason.rule-not-enabled'),
      },
    ]);
  });
});
