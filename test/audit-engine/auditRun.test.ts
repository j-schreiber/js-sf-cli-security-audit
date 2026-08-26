import fs from 'node:fs';
import path from 'node:path';
import { expect, assert } from 'chai';
import { Messages } from '@salesforce/core';
import { merge } from '@salesforce/kit';
import { PartialDeep } from '@salesforce/kit/lib/nodash/support.js';
import AuditTestContext from '../mocks/auditTestContext.js';
import { AuditRunConfig, loadAuditConfig, saveAuditConfig, startAuditRun } from '../../src/libs/audit-engine/index.js';

const TEST_DIR_BASE_PATH = path.join('test', 'mocks', 'data', 'audit-configs');
const DEFAULT_TEST_OUTPUT_DIR = path.join(TEST_DIR_BASE_PATH, 'tmp-1');
const TMP_CONFIGS_DIR = path.join('tmp', 'test-configs');

function buildPath(dirName: string) {
  return path.join(TEST_DIR_BASE_PATH, dirName);
}

/**
 * Copies a template audit-config from commited test dir
 * to an ephemeral tmp dir and returns the path.
 *
 * @param dirName
 */
function copyFromDir(dirName: string, overrides?: PartialDeep<AuditRunConfig>): string {
  const sourceConfig = path.join(TEST_DIR_BASE_PATH, dirName);
  const targetDir = path.join(TMP_CONFIGS_DIR, `${Date.now()}`);
  fs.cpSync(sourceConfig, targetDir, { recursive: true });
  const config = loadAuditConfig(targetDir);
  if (overrides) {
    merge(config, overrides);
    saveAuditConfig(targetDir, config);
  }
  return targetDir;
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
    fs.rmSync(TMP_CONFIGS_DIR, { recursive: true, force: true });
  });

  it('executes all loaded policies', async () => {
    // Arrange
    const dirPath = buildPath('full-valid');

    // Act
    const audit = startAuditRun(dirPath);
    const auditResult = await audit.execute($$.coreConnection);

    // Assert
    expect(audit.enabledPolicies()).to.have.keys(['profiles', 'users', 'permissionSets', 'objects', 'connectedApps']);
    expect(auditResult.isCompliant).to.be.true;
    assert.isDefined(auditResult.policies);
    assert.isDefined(auditResult.policies.profiles);
    assert.isDefined(auditResult.policies.permissionSets);
    assert.isDefined(auditResult.policies.users);
    assert.isDefined(auditResult.policies.objects);
    expect(auditResult.policies.profiles.isCompliant).to.be.true;
    expect(auditResult.policies.permissionSets.isCompliant).to.be.true;
    expect(auditResult.policies.profiles.executedRules).to.have.keys(['EnforcePermissionClassifications']);
    expect(auditResult.policies.permissionSets.executedRules).to.have.keys(['EnforcePermissionClassifications']);
    expect(auditResult.policies.objects.executedRules).to.have.keys(['PrivateExternalAccessForAllObjects']);
  });

  it('filters executed policies from available policies and audit scope', async () => {
    // Arrange
    const dirPath = buildPath('full-valid');

    // Act
    const audit = startAuditRun(dirPath);
    const auditResult = await audit.execute($$.coreConnection, { policies: ['users', 'objects'] });

    // Assert
    expect(audit.enabledPolicies()).to.have.keys(['users', 'objects']);
    expect(auditResult.isCompliant).to.be.true;
    assert.isDefined(auditResult.policies);
    assert.isDefined(auditResult.policies.users);
    assert.isDefined(auditResult.policies.objects);
    assert.isUndefined(auditResult.policies.profiles);
    assert.isUndefined(auditResult.policies.permissionSets);
  });

  it('runs a disabled policy when audit scope enforces it', async () => {
    // Arrange
    const dirPath = copyFromDir('minimal', { policies: { profiles: { enabled: false } } });

    // Act
    const audit = startAuditRun(dirPath);
    const auditResult = await audit.execute($$.coreConnection, { policies: ['profiles'] });

    // Assert
    expect(audit.enabledPolicies()).to.have.keys(['profiles']);
    expect(auditResult.isCompliant).to.be.true;
    assert.isDefined(auditResult.policies);
    assert.isDefined(auditResult.policies.profiles);
    expect(auditResult.policies.profiles.enabled).to.be.true;
  });

  it('ignores a non-existing policy even when it is scoped', async () => {
    // Arrange
    const dirPath = copyFromDir('minimal');

    // Act
    const audit = startAuditRun(dirPath);
    const auditResult = await audit.execute($$.coreConnection, { policies: ['users', 'profiles'] });

    // Assert
    expect(audit.enabledPolicies()).to.have.keys(['profiles']);
    expect(auditResult.isCompliant).to.be.true;
    assert.isDefined(auditResult.policies);
    assert.isDefined(auditResult.policies.profiles);
    assert.isUndefined(auditResult.policies.users);
  });

  it('reports non-compliance if one policy is not compliant', async () => {
    // Arrange
    const dirPath = buildPath('non-compliant');
    const audit = startAuditRun(dirPath);

    // Act
    const auditResult = await audit.execute($$.coreConnection);

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
    audit.config.policies.profiles!.enabled = false;

    // Act
    const auditResult = await audit.execute($$.coreConnection);

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
    audit.config.policies.connectedApps!.rules.AllUsedAppsUnderManagement.enabled = false;

    // Act
    const auditResult = await audit.execute($$.coreConnection);

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
    audit.config.policies.profiles!.enabled = false;
    const auditResult = await audit.execute($$.coreConnection);

    // Assert
    expect(auditResult.isCompliant).to.be.true;
    assert.isDefined(auditResult.policies);
    assert.isDefined(auditResult.policies.profiles);
    expect(auditResult.policies.profiles.enabled).to.be.false;
  });

  it('emits all stage-lifecycle events during a full audit run', async () => {
    // Arrange
    const stageListener = $$.context.SANDBOX.stub();
    const dirPath = buildPath('full-valid');
    const audit = startAuditRun(dirPath);
    audit.addListener('stageupdate', stageListener);

    // Act
    await audit.execute($$.coreConnection);

    // Assert
    expect(stageListener.callCount).to.equal(5);
    expect(stageListener.args.flat()).to.deep.equal([
      {
        newStage: 'initialising',
      },
      {
        newStage: 'resolving',
      },
      {
        newStage: 'executing',
      },
      {
        newStage: 'finalising',
      },
      {
        newStage: 'completed',
      },
    ]);
  });

  it('applies accepted risks from audit config to rule violations', async () => {
    // Act
    const dirPath = buildPath('full-valid');
    const audit = startAuditRun(dirPath);
    const auditResult = await audit.execute($$.coreConnection);

    // Assert
    const enforcePerms = auditResult.policies.profiles?.executedRules.EnforcePermissionClassifications;
    assert.isDefined(enforcePerms);
    expect(enforcePerms.violations).to.deep.equal([]);
    expect(enforcePerms.mutedViolations).to.have.lengthOf(2);
    const noStandardProfiles = auditResult.policies.users?.executedRules.NoStandardProfilesOnActiveUsers;
    assert.isDefined(noStandardProfiles);
    expect(noStandardProfiles.violations).to.deep.equal([]);
    expect(noStandardProfiles.mutedViolations).to.have.lengthOf(2);
  });

  it('correctly applies risks with edge-cases to audit results', async () => {
    // Arrange
    // as it turns out, the underlying bug for this edge case test was
    // that connectedApps policy identified itself as "users" policy
    // in the constructor. Let this be a reminder.
    $$.mocks.mockOAuthTokens('oauth-usage');

    // Act
    const dirPath = buildPath('edge-case-risks');
    const audit = startAuditRun(dirPath);
    const auditResult = await audit.execute($$.coreConnection);

    // Assert
    const appsUnderMgmt = auditResult.policies.connectedApps?.executedRules.AllUsedAppsUnderManagement;
    assert.isDefined(appsUnderMgmt);
    expect(appsUnderMgmt.compliantEntities).to.deep.equal(['Test App 2', 'AI Platform Auth']);
  });

  it('returns all triggered accepted risks with usage statistics in audit result', async () => {
    // Act
    const dirPath = buildPath('full-valid');
    const audit = startAuditRun(dirPath);
    const auditResult = await audit.execute($$.coreConnection);

    // Assert
    // 4 rules in total define risks, each risk-matcher is counted individually
    expect(auditResult.acceptedRisks).to.have.lengthOf(9);
    // user risk matchers
    expect(auditResult.acceptedRisks[0].appliedCount).to.equal(0);
    expect(auditResult.acceptedRisks[1].appliedCount).to.equal(1);
    expect(auditResult.acceptedRisks[2].appliedCount).to.equal(1);
    // profile risk matchers
    expect(auditResult.acceptedRisks.at(-2)!.appliedCount).to.equal(1);
    expect(auditResult.acceptedRisks.at(-1)!.appliedCount).to.equal(1);
  });
});
