import { assert, expect } from 'chai';
import { OrgDescribe } from '../../src/salesforce/index.js';
import AuditTestContext from '../mocks/auditTestContext.js';

describe('org metadata describe', () => {
  const $$ = new AuditTestContext();

  beforeEach(async () => {
    await $$.init();
  });

  afterEach(async () => {
    $$.reset();
  });

  it('lists all availble user permission from target org', async () => {
    // Arrange
    // it appears that some permissions can be assigned (and are available in metadata / source)
    // but they are NOT present in the permission set / profile describe. The most prominent example
    // is the new CanApproveUninstalledApps permission (the corresponding field would have been
    // PermissionsCanApproveUninstalledApps, which does not exist).
    // To remedy that, we parse metadata of all profiles additional to PermissionSet describe.

    // Act
    const org = await OrgDescribe.create($$.targetOrgConnection);
    const userPerms = org.getUserPermissions();

    // Assert
    expect(userPerms).to.have.lengthOf(424); // permset has 418, profiles have additional 6
    // these are the permissions from our prod that are part of profiles,
    // but not part of the permset describe. No idea which is the 6th one
    const missingPermsFromMetadata = [
      'CanApproveUninstalledApps',
      'ManagePackageLicenses',
      'ViewConsumption',
      'ViewFlowUsageAndFlowEventData',
      'AllowObjectDetectionTraining',
    ];
    missingPermsFromMetadata.forEach((permName) => {
      const perm = userPerms.find((userPerm) => userPerm.name === permName);
      assert.isDefined(perm);
    });
  });

  it('lists all available custom permissions from target org', async () => {
    // Act
    const org = await OrgDescribe.create($$.targetOrgConnection);
    const customPerms = org.getCustomPermissions();

    // Assert
    // mock query from audit context returns 3 permission
    expect(customPerms).to.have.lengthOf(3);
  });

  it('correctly evaluates if a user permission exists on the target org', async () => {
    // Act
    const org = await OrgDescribe.create($$.targetOrgConnection);

    // Assert
    const existingPerms = ['AuthorApex', 'ViewSetup', 'CanApproveUninstalledApps', 'Packaging2'];
    for (const perm of existingPerms) {
      // eslint-disable-next-line no-await-in-loop
      expect(org.isValid(perm)).to.be.true;
    }
    const nonExistingPerms = ['Something', 'SmthElse', '', ' '];
    for (const perm of nonExistingPerms) {
      // eslint-disable-next-line no-await-in-loop
      expect(org.isValid(perm)).to.be.false;
    }
  });
});
