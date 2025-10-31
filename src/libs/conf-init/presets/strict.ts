import { PermissionRiskLevel } from '../../core/classification-types.js';
import NonePreset from './none.js';

export default class StrictPreset extends NonePreset {
  public constructor() {
    super({
      UseAnyApiClient: PermissionRiskLevel.BLOCKED,
      CustomizeApplication: PermissionRiskLevel.CRITICAL,
      ModifyMetadata: PermissionRiskLevel.CRITICAL,
      AuthorApex: PermissionRiskLevel.CRITICAL,
      ManageAuthProviders: PermissionRiskLevel.CRITICAL,
      Packaging2: PermissionRiskLevel.CRITICAL,
      Packaging2Delete: PermissionRiskLevel.CRITICAL,
      Packaging2PromoteVersion: PermissionRiskLevel.CRITICAL,
      InstallPackaging: PermissionRiskLevel.CRITICAL,
      ViewClientSecret: PermissionRiskLevel.CRITICAL,
      ExportReport: PermissionRiskLevel.HIGH,
      ViewSetup: PermissionRiskLevel.HIGH,
      ApiEnabled: PermissionRiskLevel.HIGH,
      ViewAllData: PermissionRiskLevel.HIGH,
      ModifyAllData: PermissionRiskLevel.HIGH,
      ManageTwoFactor: PermissionRiskLevel.HIGH,
      ManageRemoteAccess: PermissionRiskLevel.HIGH,
      CanApproveUninstalledApps: PermissionRiskLevel.HIGH,
      EmailMass: PermissionRiskLevel.MEDIUM,
    });
  }
}
