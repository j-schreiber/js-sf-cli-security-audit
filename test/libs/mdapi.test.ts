import path from 'node:path';
import { expect } from 'chai';
import { ComponentSet, MetadataApiRetrieve, RequestStatus, RetrieveResult } from '@salesforce/source-deploy-retrieve';
import AuditTestContext, { MOCK_DATA_BASE_PATH, RETRIEVES_BASE } from '../mocks/auditTestContext.js';
import MDAPI, { NamedTypesRegistry, SingletonRegistry } from '../../src/libs/core/mdapi/mdapiRetriever2.js';

export const MOCKS_BASE_PATH = path.join(MOCK_DATA_BASE_PATH, 'mdapi-retrieve-mocks');

describe('audit config', () => {
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
    const retrieveStub = $$.context.SANDBOX.stub(ComponentSet.prototype, 'retrieve').resolves(
      new PermissionSetsRetrieveMock() as MetadataApiRetrieve
    );

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
    const retrieveStub = $$.context.SANDBOX.stub(ComponentSet.prototype, 'retrieve').resolves(
      new ConnectedAppSettingsMock() as MetadataApiRetrieve
    );

    // Act
    const mdapi = new MDAPI($$.targetOrgConnection);
    const settings = await mdapi.resolveSingleton('ConnectedAppSettings');

    // Assert
    expect(settings.enableAdminApprovedAppsOnly).to.be.true;
    expect(retrieveStub.callCount).to.equal(1);
  });
});

class PermissionSetsRetrieveMock {
  // eslint-disable-next-line class-methods-use-this
  public async pollStatus(): Promise<RetrieveResult> {
    const cmpSet = ComponentSet.fromSource(path.join(MOCKS_BASE_PATH, 'default-permsets'));
    return new RetrieveResult(
      { done: true, status: RequestStatus.Succeeded, success: true, fileProperties: [], id: '1', zipFile: '' },
      cmpSet
    );
  }
}

class ConnectedAppSettingsMock {
  // eslint-disable-next-line class-methods-use-this
  public async pollStatus(): Promise<RetrieveResult> {
    const cmpSet = ComponentSet.fromSource(path.join(MOCKS_BASE_PATH, 'security-settings'));
    return new RetrieveResult(
      { done: true, status: RequestStatus.Succeeded, success: true, fileProperties: [], id: '2', zipFile: '' },
      cmpSet
    );
  }
}
