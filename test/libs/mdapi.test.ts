import path from 'node:path';
import { expect } from 'chai';
import { ComponentSet, MetadataApiRetrieve, RequestStatus, RetrieveResult } from '@salesforce/source-deploy-retrieve';
import AuditTestContext, { MOCK_DATA_BASE_PATH, RETRIEVES_BASE } from '../mocks/auditTestContext.js';
import MDAPI, { Registry } from '../../src/libs/core/mdapi/mdapiRetriever2.js';

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
    const parsedPermset = Registry.PermissionSet.parse(permsetPath);

    // Assert
    expect(parsedPermset.label).to.equal('Test_Admin_Permission_Set_1');
  });

  it('produces connected app settings from source file without root node', async () => {
    // Act
    const filePath = path.join(RETRIEVES_BASE, 'connected-app-settings', 'api-security-controls-available-enabled.xml');
    const parsedSetting = Registry.ConnectedAppSettings.parse(filePath);

    // Assert
    expect(parsedSetting.enableAdminApprovedAppsOnly).to.be.true;
  });

  it('returns strongly typed content of retrieved permission sets', async () => {
    // Arrange
    $$.context.SANDBOX.stub(ComponentSet.prototype, 'retrieve').resolves(
      new PermissionSetsRetrieveMock() as MetadataApiRetrieve
    );

    // Act
    const mdapi = new MDAPI($$.targetOrgConnection);
    const permSetNames = ['Test_Admin_Permission_Set_1', 'Test_Standard_User_Permission_Set_1'];
    const permsets = await mdapi.resolve('PermissionSet', permSetNames);

    // Assert
    expect(Object.keys(permsets)).to.deep.equal(permSetNames);
  });

  it('returns strongly typed content of retrieved connected app settings', async () => {
    // Arrange
    $$.context.SANDBOX.stub(ComponentSet.prototype, 'retrieve').resolves(
      new ConnectedAppSettingsMock() as MetadataApiRetrieve
    );

    // Act
    const mdapi = new MDAPI($$.targetOrgConnection);
    const settings = await mdapi.resolve('ConnectedAppSettings');

    // Assert
    expect(settings.enableAdminApprovedAppsOnly).to.be.true;
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
