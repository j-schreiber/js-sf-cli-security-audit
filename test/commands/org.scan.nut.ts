import path from 'node:path';
import { execCmd, TestSession } from '@salesforce/cli-plugins-testkit';
import { assert, expect } from 'chai';
import { OrgUserPermScanResult } from '../../src/commands/org/scan/user-perms.js';

const scratchOrgAlias = 'QuickScanNutsOrg';
const testingWorkingDir = path.join('test', 'mocks', 'test-sfdx-project');

describe('org quick-scan NUTs', () => {
  let session: TestSession;

  before(async () => {
    session = await TestSession.create({
      project: {
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

  it('scans all profiles and permission sets for valid existing permissions', () => {
    // Act
    const command = `org scan user-perms --target-org ${scratchOrgAlias} --name AuthorApex --name CanApproveUninstalledApps --json`;
    const result = execCmd<OrgUserPermScanResult>(command, { ensureExitCode: 0 }).jsonOutput?.result;

    // Assert
    assert.isDefined(result);
    assert.isDefined(result.permissions.AuthorApex);
    assert.isDefined(result.permissions.CanApproveUninstalledApps);
    expect(result.permissions.AuthorApex.profiles).to.include('System Administrator');
    expect(result.permissions.CanApproveUninstalledApps.profiles).to.include('System Administrator');
  });

  it('includes users assignments for each permission when --deep-scan flag is given', () => {
    // Act
    const command = `org scan user-perms --target-org ${scratchOrgAlias} --name ViewSetup --deep-scan --json`;
    const result = execCmd<OrgUserPermScanResult>(command, { ensureExitCode: 0 }).jsonOutput?.result;

    // Assert
    assert.isDefined(result);
    assert.isDefined(result.permissions.ViewSetup);
    expect(result.permissions.ViewSetup.profiles).to.include('System Administrator');
    assert.isDefined(result.permissions.ViewSetup.users);
    expect(result.permissions.ViewSetup.users).to.not.be.empty;
  });

  it('gracefully ignores an unknown permission in the result', () => {
    // Act
    const command = `org scan user-perms --target-org ${scratchOrgAlias} --name DoesNotExist --json`;
    const result = execCmd<OrgUserPermScanResult>(command, { ensureExitCode: 0 }).jsonOutput?.result;

    // Assert
    assert.isDefined(result);
    expect(result.permissions.DoesNotExist).to.be.undefined;
  });
});
