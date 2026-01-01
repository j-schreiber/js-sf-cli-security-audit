import fs from 'node:fs';
import path from 'node:path';
import { expect, assert } from 'chai';
import { Messages } from '@salesforce/core';
import AuditTestContext from '../mocks/auditTestContext.js';
import { startAuditRun } from '../../src/libs/core/auditRun.js';

const TEST_DIR_BASE_PATH = path.join('test', 'mocks', 'data', 'audit-configs');
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
    assert.isDefined(auditResult.policies.profiles);
    assert.isDefined(auditResult.policies.permissionSets);
    assert.isDefined(auditResult.policies.users);
    expect(auditResult.policies.profiles.isCompliant).to.be.true;
    expect(auditResult.policies.permissionSets.isCompliant).to.be.true;
    expect(Object.keys(auditResult.policies.profiles.executedRules)).to.deep.equal([
      'EnforcePermissionClassifications',
    ]);
    expect(Object.keys(auditResult.policies.permissionSets.executedRules)).to.deep.equal([
      'EnforcePermissionClassifications',
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
    assert.isDefined(auditResult.policies.profiles);
    expect(auditResult.policies.profiles.isCompliant).to.be.false;
    assert.isDefined(auditResult.policies.profiles.executedRules.EnforcePermissionClassifications);
    expect(auditResult.policies.profiles.executedRules.EnforcePermissionClassifications.isCompliant).to.be.false;
  });

  it('runs and resolves only enabled policies', async () => {
    // Arrange
    const dirPath = buildPath('full-valid');
    const audit = startAuditRun(dirPath);
    audit.configs.policies.profiles!.content.enabled = false;

    // Act
    const auditResult = await audit.execute(await $$.targetOrg.getConnection());

    // Assert
    expect(auditResult.isCompliant).to.be.true;
    assert.isDefined(auditResult.policies);
    assert.isDefined(auditResult.policies.profiles);
    expect(auditResult.policies.profiles.auditedEntities).to.deep.equal([]);
    // ensure that "disabled" policies are not printed in data table
    expect(auditResult.policies.profiles.enabled).to.be.false;
  });

  it('runs only enabled rules on policy', async () => {
    // Arrange
    const dirPath = buildPath('full-valid');
    const audit = startAuditRun(dirPath);
    audit.configs.policies.connectedApps!.content.rules.AllUsedAppsUnderManagement.enabled = false;

    // Act
    const auditResult = await audit.execute(await $$.targetOrg.getConnection());

    // Assert
    expect(auditResult.isCompliant).to.be.true;
    assert.isDefined(auditResult.policies);
    assert.isDefined(auditResult.policies.connectedApps);
    expect(auditResult.policies.connectedApps.enabled).to.equal(true);
    expect(Object.keys(auditResult.policies.connectedApps.executedRules)).to.deep.equal(['NoUserCanSelfAuthorize']);
    expect(auditResult.policies.connectedApps.skippedRules).to.deep.equal([
      {
        name: 'AllUsedAppsUnderManagement',
        skipReason: generalPolicyMessages.getMessage('skip-reason.rule-not-enabled'),
      },
    ]);
  });

  it('exits gracefully if policies exist but all are disabled', async () => {
    // Act
    const audit = startAuditRun(buildPath('minimal'));
    audit.configs.policies.profiles!.content.enabled = false;
    const auditResult = await audit.execute(await $$.targetOrg.getConnection());

    // Assert
    expect(auditResult.isCompliant).to.be.true;
    assert.isDefined(auditResult.policies);
    assert.isDefined(auditResult.policies.profiles);
    expect(auditResult.policies.profiles.enabled).to.be.false;
  });

  it('returns executable rules from a resolved policy', async () => {
    // Act
    const audit = startAuditRun(buildPath('full-valid'));
    await audit.resolve($$.targetOrgConnection);

    // Assert
    expect(audit.getExecutableRulesCount('profiles')).to.equal(1);
    expect(audit.getExecutableRulesCount('permissionSets')).to.equal(1);
    expect(audit.getExecutableRulesCount('connectedApps')).to.equal(2);
  });
});
