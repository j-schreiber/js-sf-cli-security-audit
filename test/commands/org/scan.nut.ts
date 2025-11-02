import path from 'node:path';
import { execCmd, TestSession } from '@salesforce/cli-plugins-testkit';
import { assert, expect } from 'chai';
import { OrgUserPermScanResult } from '../../../src/commands/org/scan/user-perm.js';

const scratchOrgAlias = 'QuickScanNutsOrg';
const testingWorkingDir = path.join('test', 'mocks', 'test-sfdx-project');

describe('org quick-scan NUTs', () => {
  let session: TestSession;

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

  it('scans all profiles and permission sets for valid existing permissions', () => {
    // Act
    const command = `org quick-scan --target-org ${scratchOrgAlias} --name AuthorApex --name CanApproveUninstalledApps`;
    const result = execCmd<OrgUserPermScanResult>(command, { ensureExitCode: 0 }).jsonOutput?.result;

    // Assert
    assert.isDefined(result);
    assert.isDefined(result.AuthorApex);
    assert.isDefined(result.CanApproveUninstalledApps);
    expect(result.AuthorApex.profiles).to.deep.include(['System Administrator']);
    expect(result.CanApproveUninstalledApps.profiles).to.deep.include(['System Administrator']);
  });

  it('gracefully ignores an unknown permission in the result', () => {
    // Act
    const command = `org quick-scan --target-org ${scratchOrgAlias} --name DoesNotExist`;
    const result = execCmd<OrgUserPermScanResult>(command, { ensureExitCode: 0 }).jsonOutput?.result;

    // Assert
    assert.isDefined(result);
    expect(result.DoesNotExist).to.be.undefined;
  });
});
