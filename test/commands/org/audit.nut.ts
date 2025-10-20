import fs from 'node:fs';
import path from 'node:path';
import { assert, expect } from 'chai';
import { execCmd, TestSession } from '@salesforce/cli-plugins-testkit';
import { OrgAuditInitResult } from '../../../src/commands/org/audit/init.js';
import { OrgAuditRunResult } from '../../../src/commands/org/audit/run.js';
import { PermissionRiskLevelPresets } from '../../../src/libs/policies/types.js';
import AuditConfigFileManager from '../../../src/libs/config/audit-run/auditConfigFileManager.js';

const scratchOrgAlias = 'TestTargetOrg';
const testingWorkingDir = path.join('test', 'mocks', 'test-sfdx-project');

describe('org audit NUTs', () => {
  let session: TestSession;

  function checkFileExists(filePath: string): boolean {
    const localFilePath = resolveTestDirFilePath(filePath);
    return fs.existsSync(localFilePath);
  }

  function resolveTestDirFilePath(filePath: string) {
    return path.join(session.dir, 'test-sfdx-project', filePath);
  }

  function activatePolicies(dirPath: string, preset: PermissionRiskLevelPresets) {
    const fileManager = new AuditConfigFileManager();
    const configDirPath = resolveTestDirFilePath(dirPath);
    const conf = fileManager.parse(configDirPath);
    if (conf.policies.Profiles?.content.profiles) {
      Object.values(conf.policies.Profiles.content.profiles).forEach((profile) => {
        // eslint-disable-next-line no-param-reassign
        profile.preset = preset;
      });
    }
    if (conf.policies.PermissionSets?.content.permissionSets) {
      Object.values(conf.policies.PermissionSets.content.permissionSets).forEach((permSet) => {
        // eslint-disable-next-line no-param-reassign
        permSet.preset = preset;
      });
    }
    fileManager.save(configDirPath, conf);
  }

  before(async () => {
    session = await TestSession.create({
      project: {
        name: 'orgAuditNuts',
        sourceDir: testingWorkingDir,
      },
      devhubAuthStrategy: 'AUTO',
      scratchOrgs: [
        {
          alias: scratchOrgAlias,
          config: path.join('config', 'default-scratch-def.json'),
          setDefault: true,
          duration: 1,
        },
      ],
    });
  });

  after(async () => {
    await session?.clean();
  });

  afterEach(async () => {
    // clean audit config files?
  });

  it('initialises a full audit config with policies and classifications from org', () => {
    // Act
    const result = execCmd<OrgAuditInitResult>(
      `org:audit:init --target-org ${scratchOrgAlias} --output-dir tmp --json`,
      { ensureExitCode: 0 }
    ).jsonOutput?.result;

    // Assert
    assert.isDefined(result);
    assert.isDefined(result.classifications.userPermissions);
    assert.isDefined(result.classifications.userPermissions.filePath);
    expect(checkFileExists(result.classifications.userPermissions.filePath)).to.be.true;
    assert.isDefined(result.policies.Profiles);
    assert.isDefined(result.policies.Profiles.filePath);
    expect(checkFileExists(result.policies.Profiles.filePath)).to.be.true;
  });

  it('successfully completes an audit without technical errors from default config', () => {
    // Act
    // relies on the config that was created from the first test
    const result = execCmd<OrgAuditRunResult>(`org:audit:run --target-org ${scratchOrgAlias} --source-dir tmp --json`, {
      ensureExitCode: 0,
    }).jsonOutput?.result;

    // Assert
    assert.isDefined(result);
    assert.isDefined(result.auditDate);
    assert.isDefined(result.orgId);
    assert.isDefined(result.policies);
  });

  it('successfully completes an audit with all policies active', async () => {
    // Arrange
    activatePolicies('tmp', PermissionRiskLevelPresets.ADMIN);

    // Act
    // relies on the config that was created from the first test
    const result = execCmd<OrgAuditRunResult>(`org:audit:run --target-org ${scratchOrgAlias} --source-dir tmp --json`, {
      ensureExitCode: 0,
    }).jsonOutput?.result;

    // Assert
    assert.isDefined(result);
    expect(Object.keys(result.policies)).to.deep.equal(['Profiles', 'PermissionSets', 'ConnectedApps']);
    Object.entries(result.policies).forEach(([policyName, policy]) => {
      // every policy should have at least one audited entity
      expect(policy.auditedEntities, policyName).not.deep.equal([]);
    });
  });
});
