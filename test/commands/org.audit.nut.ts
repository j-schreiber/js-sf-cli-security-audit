import fs from 'node:fs';
import path from 'node:path';
import { assert, expect } from 'chai';
import { execCmd, TestSession } from '@salesforce/cli-plugins-testkit';
import { OrgAuditInitResult } from '../../src/commands/org/audit/init.js';
import { OrgAuditRunResult } from '../../src/commands/org/audit/run.js';
import { ConfigFileManager, UserPrivilegeLevel } from '../../src/libs/audit-engine/index.js';
import { fixDevHubAuthFromJWT } from '../mocks/authHelper.js';

const enterpriseOrgAlias = 'TestTargetOrg';
const professionalOrgAlias = 'ProfTestTargetOrg';
const testingWorkingDir = path.join('test', 'mocks', 'test-sfdx-project');

describe('org audit NUTs', () => {
  let session: TestSession;

  function checkFileExists(filePath?: string): boolean {
    assert.isDefined(filePath);
    const localFilePath = resolveTestDirFilePath(filePath);
    return fs.existsSync(localFilePath);
  }

  function resolveTestDirFilePath(filePath: string) {
    return path.join(session.dir, 'test-sfdx-project', filePath);
  }

  function activateClassifications(dirPath: string, role: UserPrivilegeLevel) {
    const configDirPath = resolveTestDirFilePath(dirPath);
    const conf = ConfigFileManager.parse(configDirPath);
    if (conf.classifications.profiles?.profiles) {
      for (const profile of Object.values(conf.classifications.profiles.profiles)) {
        // eslint-disable-next-line no-param-reassign
        profile.role = role;
      }
    }
    if (conf.classifications.permissionSets?.permissionSets) {
      for (const profile of Object.values(conf.classifications.permissionSets.permissionSets)) {
        // eslint-disable-next-line no-param-reassign
        profile.role = role;
      }
    }
    ConfigFileManager.save(configDirPath, conf);
  }

  before(async () => {
    if (process.env.TESTKIT_JWT_CLIENT_ID) {
      const authFields = await fixDevHubAuthFromJWT();
      assert.isDefined(authFields.username);
    }
    session = await TestSession.create({
      project: {
        name: 'orgAuditNuts',
        sourceDir: testingWorkingDir,
      },
      devhubAuthStrategy: 'AUTO',
      scratchOrgs: [
        {
          alias: enterpriseOrgAlias,
          config: path.join('config', 'default-scratch-def.json'),
          setDefault: true,
          duration: 1,
        },
        {
          alias: professionalOrgAlias,
          config: path.join('config', 'prof-edition-scratch-def.json'),
          setDefault: false,
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

  it('initialises a full audit config from enterprise org at target directory', () => {
    // Act
    const result = execCmd<OrgAuditInitResult>(
      `org:audit:init --target-org ${enterpriseOrgAlias} --output-dir tmp --json`,
      { ensureExitCode: 0 }
    ).jsonOutput?.result;

    // Assert
    assert.isDefined(result);
    assert.isDefined(result.classifications.userPermissions);
    assert.isDefined(result.classifications.userPermissions.filePath);
    expect(checkFileExists(result.classifications.userPermissions.filePath)).to.be.true;
    assert.isDefined(result.policies.profiles);
    assert.isDefined(result.policies.profiles.filePath);
    expect(checkFileExists(result.policies.profiles.filePath)).to.be.true;
  });

  it('initialises a full audit config from professional org at target directory', () => {
    // Act
    const result = execCmd<OrgAuditInitResult>(
      `org:audit:init --target-org ${professionalOrgAlias} --output-dir prof_ed --json`,
      { ensureExitCode: 0 }
    ).jsonOutput?.result;

    // Assert
    assert.isDefined(result);
    assert.isDefined(result.classifications.userPermissions);
    assert.isDefined(result.classifications.userPermissions.filePath);
    expect(checkFileExists(result.classifications.userPermissions.filePath)).to.be.true;
    assert.isDefined(result.policies.profiles);
    assert.isDefined(result.policies.profiles.filePath);
    expect(checkFileExists(result.policies.profiles.filePath)).to.be.true;
  });

  it('successfully completes an audit without technical errors from default config', () => {
    // Act
    // relies on the config that was created from the first test
    const result = execCmd<OrgAuditRunResult>(
      `org:audit:run --target-org ${enterpriseOrgAlias} --source-dir tmp --json`,
      {
        ensureExitCode: 0,
      }
    ).jsonOutput?.result;

    // Assert
    assert.isDefined(result);
    assert.isDefined(result.auditDate);
    assert.isDefined(result.orgId);
    assert.isDefined(result.policies);
  });

  it('successfully completes an audit of enterprise ed with all policies active', async () => {
    // Arrange
    activateClassifications('tmp', UserPrivilegeLevel.ADMIN);

    // Act
    // relies on the config that was created from the first test
    const result = execCmd<OrgAuditRunResult>(
      `org:audit:run --target-org ${enterpriseOrgAlias} --source-dir tmp --json`,
      {
        ensureExitCode: 0,
      }
    ).jsonOutput?.result;

    // Assert
    assert.isDefined(result);
    expect(Object.keys(result.policies)).to.deep.equal([
      'profiles',
      'permissionSets',
      'connectedApps',
      'users',
      'settings',
    ]);
    for (const [policyName, policy] of Object.entries(result.policies)) {
      // every policy should have at least one audited entity
      expect(policy.auditedEntities, 'audited entities for: ' + policyName).not.deep.equal([]);
    }
  });

  it('successfully completes an audit of professional ed with all policies active', async () => {
    // Arrange
    activateClassifications('prof_ed', UserPrivilegeLevel.ADMIN);

    // Act
    // relies on the config that was created from the first test
    const result = execCmd<OrgAuditRunResult>(
      `org:audit:run --target-org ${professionalOrgAlias} --source-dir prof_ed --json`,
      {
        ensureExitCode: 0,
      }
    ).jsonOutput?.result;

    // Assert
    assert.isDefined(result);
    // each policy was executed
    expect(Object.keys(result.policies)).to.deep.equal([
      'profiles',
      'permissionSets',
      'connectedApps',
      'users',
      'settings',
    ]);
  });

  it('initialises a full audit config at root directory', () => {
    // Act
    const initResult = execCmd<OrgAuditInitResult>(`org:audit:init --target-org ${enterpriseOrgAlias} --json`, {
      ensureExitCode: 0,
    }).jsonOutput?.result;

    // Assert
    assert.isDefined(initResult);
    assert.isDefined(initResult.classifications.userPermissions?.filePath);
    expect(checkFileExists(initResult.classifications.userPermissions.filePath)).to.be.true;
    expect(checkFileExists(initResult.policies.profiles?.filePath)).to.be.true;
  });

  it('successfully executes an audit run from root directory', () => {
    // Act
    const runResult = execCmd<OrgAuditRunResult>(`org:audit:run --target-org ${enterpriseOrgAlias} --json`, {
      ensureExitCode: 0,
    }).jsonOutput?.result;

    // Assert
    assert.isDefined(runResult);
  });

  it('successfully executes audit with problematic .forceignore', () => {
    // Arrange
    // https://github.com/j-schreiber/js-sf-cli-security-audit/issues/12
    // when a .forceignore file is present (content does not matter), source
    // retrieve with ComponentSet failed. Even though MDAPI still returned
    // the files, they were not successfully converted (getSourceComponents).
    // the only workaround I found was to retrieve metadata files, and handle
    // the file content parsing myself, without conversion to "source" format.
    fs.writeFileSync(resolveTestDirFilePath('.forceignore'), 'package.xml');

    // Act
    const cmdResult = execCmd<OrgAuditRunResult>(`org:audit:run --target-org ${enterpriseOrgAlias} --json`, {
      ensureExitCode: 0,
    });

    // Assert
    // we already ensureExitCode 0, so this is ok
    expect(cmdResult).to.be.ok;
  });
});
