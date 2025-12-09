import path from 'node:path';
import fs from 'node:fs';
import { expect } from 'chai';
import { ApexSettings, SecuritySettings } from '@jsforce/jsforce-node/lib/api/metadata.js';
import AuditTestContext, { MOCK_DATA_BASE_PATH, parseXmlFile, RETRIEVES_BASE } from '../mocks/auditTestContext.js';
import MDAPI, { NamedTypesRegistry, SingletonRegistry } from '../../src/libs/core/mdapi/mdapiRetriever.js';
import { RETRIEVE_CACHE } from '../../src/libs/core/constants.js';
import AnySettingsMetadata from '../../src/libs/core/mdapi/anySettingsMetadata.js';

export const MOCKS_BASE_PATH = path.join(MOCK_DATA_BASE_PATH, 'mdapi-retrieve-mocks');

describe('mdapi retriever', () => {
  const $$ = new AuditTestContext();

  beforeEach(async () => {
    await $$.init();
  });

  afterEach(async () => {
    $$.reset();
  });

  it('produces permission set from source file without root node', async () => {
    // Act
    const permsetPath = path.join(
      RETRIEVES_BASE,
      'full-permsets',
      'Test_Admin_Permission_Set_1.permissionset-meta.xml'
    );
    const parsedPermset = NamedTypesRegistry.PermissionSet.parse(permsetPath);

    // Assert
    expect(parsedPermset.label).to.equal('Test_Admin_Permission_Set_1');
  });

  it('fills missing content from XML parser with empty list', async () => {
    // Act
    const permsetPath = path.join(
      RETRIEVES_BASE,
      'full-permsets',
      'Test_Standard_User_Permission_Set_1.permissionset-meta.xml'
    );
    const parsedPermset = NamedTypesRegistry.PermissionSet.parse(permsetPath);

    // Assert
    expect(parsedPermset.userPermissions).to.deep.equal([]);
    expect(parsedPermset.customPermissions).to.deep.equal([]);
  });

  it('produces connected app settings from source file without root node', async () => {
    // Act
    const filePath = path.join(RETRIEVES_BASE, 'connected-app-settings', 'api-security-controls-available-enabled.xml');
    const parsedSetting = SingletonRegistry.ConnectedAppSettings.parse(filePath);

    // Assert
    expect(parsedSetting.enableAdminApprovedAppsOnly).to.be.true;
  });

  it('returns strongly typed content of retrieved permission sets', async () => {
    // Arrange
    const retrieveStub = $$.stubMetadataRetrieve('default-permsets');

    // Act
    const mdapi = new MDAPI($$.targetOrgConnection);
    const permSetNames = ['Test_Admin_Permission_Set_1', 'Test_Standard_User_Permission_Set_1'];
    const permsets = await mdapi.resolve('PermissionSet', permSetNames);

    // Assert
    expect(Object.keys(permsets)).to.deep.equal(permSetNames);
    const adminPermset = permsets['Test_Admin_Permission_Set_1'];
    expect(adminPermset.label).to.equal('Test Admin Permission Set 1');
    expect(adminPermset.userPermissions.length).to.equal(1);
    expect(adminPermset.userPermissions[0]).to.deep.equal({ enabled: true, name: 'ViewSetup' });
    const userPermset = permsets['Test_Standard_User_Permission_Set_1'];
    expect(userPermset.userPermissions.length).to.equal(0);
    expect(retrieveStub.callCount).to.equal(1);
  });

  it('returns strongly typed content of retrieved connected app settings', async () => {
    // Arrange
    const retrieveStub = $$.stubMetadataRetrieve('security-settings');

    // Act
    const mdapi = new MDAPI($$.targetOrgConnection);
    const settings = await mdapi.resolveSingleton('ConnectedAppSettings');

    // Assert
    expect(settings.enableAdminApprovedAppsOnly).to.be.true;
    expect(retrieveStub.callCount).to.equal(1);
  });

  it('caches retrieved permission sets by their full name', async () => {
    // Arrange
    const retrieveStub = $$.stubMetadataRetrieve('default-permsets');

    // Act
    const mdapi = new MDAPI($$.targetOrgConnection);
    const permSetNames = ['Test_Admin_Permission_Set_1', 'Test_Standard_User_Permission_Set_1'];
    const permsets = await mdapi.resolve('PermissionSet', permSetNames);
    const permsets2 = await mdapi.resolve('PermissionSet', ['Test_Admin_Permission_Set_1']);
    const permsets3 = await mdapi.resolve('PermissionSet', ['Test_Standard_User_Permission_Set_1']);

    // Assert
    expect(retrieveStub.callCount).to.equal(1);
    expect(Object.keys(permsets)).to.deep.equal(permSetNames);
    expect(Object.keys(permsets2)).to.deep.equal(['Test_Admin_Permission_Set_1']);
    expect(Object.keys(permsets3)).to.deep.equal(['Test_Standard_User_Permission_Set_1']);
  });

  it('caches connected app settings by its metadata type', async () => {
    // Arrange
    const retrieveStub = $$.stubMetadataRetrieve('security-settings');

    // Act
    const mdapi = new MDAPI($$.targetOrgConnection);
    const settings = await mdapi.resolveSingleton('ConnectedAppSettings');
    const settings2 = await mdapi.resolveSingleton('ConnectedAppSettings');

    // Assert
    expect(retrieveStub.callCount).to.equal(1);
    expect(settings.enableAdminApprovedAppsOnly).to.be.true;
    expect(settings2.enableAdminApprovedAppsOnly).to.be.true;
  });

  it('resolves valid profile entities from tooling API by name', async () => {
    // Act
    const mdapi = new MDAPI($$.targetOrgConnection);
    const profiles = await mdapi.resolve('Profile', ['System Administrator', 'Standard User']);

    // Assert
    expect(Object.keys(profiles)).to.deep.equal(['System Administrator', 'Standard User']);
    const adminProfile = profiles['System Administrator'];
    expect(adminProfile.userPermissions.length).to.equal(217);
  });

  it('ignores entities that do not return valid metadata', async () => {
    // Arrange
    $$.mocks.setQueryMock(
      "SELECT Name,Metadata FROM Profile WHERE Name = 'Custom Profile'",
      'profile-with-null-metadata'
    );

    // Act
    const mdapi = new MDAPI($$.targetOrgConnection);
    const profiles = await mdapi.resolve('Profile', ['Custom Profile']);

    // Assert
    expect(Object.keys(profiles)).to.deep.equal([]);
  });

  it('cleans up temporary retrieve files after doing the deed', async () => {
    // Act
    const mdapi = new MDAPI($$.targetOrgConnection);
    await mdapi.resolveSingleton('ConnectedAppSettings');

    // Assert
    expect(fs.existsSync(RETRIEVE_CACHE)).to.be.true;
    const dirEntries = fs.readdirSync(RETRIEVE_CACHE);
    expect(dirEntries.length).to.equal(0);
  });

  it('retrieves a list of valid settings and resolves their contents by name', async () => {
    // Act
    const settingsRepo = new AnySettingsMetadata();
    const settings = await settingsRepo.resolve($$.targetOrgConnection, ['Apex', 'Security', 'UserInterface']);

    // Assert
    expect(Array.from(settings.keys())).to.deep.equal(['Apex', 'Security', 'UserInterface']);
    const apexSetting = settings.get('Apex');
    const expectedApexSetting = parseXmlFile<{ ApexSettings: ApexSettings }>(
      'mdapi-retrieve-mocks',
      'full',
      'settings',
      'Apex.settings-meta.xml'
    ).ApexSettings;
    expect(apexSetting).not.to.be.undefined;
    expect(apexSetting).to.deep.equal(expectedApexSetting);
    const securitySetting = settings.get('Security');
    const expectedSecuritySetting = parseXmlFile<{ SecuritySettings: SecuritySettings }>(
      'mdapi-retrieve-mocks',
      'full',
      'settings',
      'Security.settings-meta.xml'
    ).SecuritySettings;
    expect(securitySetting).not.to.be.undefined;
    expect(securitySetting).to.deep.equal(expectedSecuritySetting);
  });

  it('ignores invalid setting names and does not throw an error', async () => {
    // Act
    const settingsRepo = new AnySettingsMetadata();
    const settings = await settingsRepo.resolve($$.targetOrgConnection, ['Apex', 'SomethingUnknown', 'AgentforceBot']);

    // Assert
    expect(Array.from(settings.keys())).to.deep.equal(['Apex']);
  });
});
