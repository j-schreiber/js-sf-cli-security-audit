import fs from 'node:fs';
import path from 'node:path';
import { assert, expect } from 'chai';
import { execCmd, TestSession } from '@salesforce/cli-plugins-testkit';
import { OrgAuditInitResult } from '../../../src/commands/org/audit/init.js';
import { OrgAuditRunResult } from '../../../src/commands/org/audit/run.js';

const scratchOrgAlias = 'TestTargetOrg';
const testingWorkingDir = path.join('test', 'mocks', 'test-sfdx-project');

describe('org audit NUTs', () => {
  let session: TestSession;

  function checkFileExists(filePath: string): boolean {
    const localFilePath = path.join(session.dir, 'test-sfdx-project', filePath);
    return fs.existsSync(localFilePath);
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
});
