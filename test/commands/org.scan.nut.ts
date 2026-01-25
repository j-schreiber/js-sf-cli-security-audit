import path from 'node:path';
import { execCmd, TestSession } from '@salesforce/cli-plugins-testkit';
import { assert, expect } from 'chai';
import { OrgUserPermScanResult } from '../../src/commands/org/scan/user-perms.js';
import { fixDevHubAuth } from '../mocks/authHelper.js';

const scratchOrgAlias = 'QuickScanNutsOrg';
const testingWorkingDir = path.join('test', 'mocks', 'test-sfdx-project');

describe('org quick-scan NUTs', () => {
  let session: TestSession;

  before(async () => {
    if (process.env.TESTKIT_JWT_CLIENT_ID) {
      fixDevHubAuth();
    }
    session = await TestSession.create({
      project: {
        name: 'orgQuickScanNuts',
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
    assert.isDefined(session.hubOrg.username);
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

  it('gracefully ignores an unknown permission in the result', () => {
    // Act
    const command = `org scan user-perms --target-org ${scratchOrgAlias} --name DoesNotExist --json`;
    const result = execCmd<OrgUserPermScanResult>(command, { ensureExitCode: 0 }).jsonOutput?.result;

    // Assert
    assert.isDefined(result);
    // not yet implemented. For now, we simply "ignore it" by reporting 0 profiles & perms
    // later, we'll validate existing perms on the org and be smarter about this
    // expect(result.permissions.DoesNotExist).to.be.undefined;
  });
});
