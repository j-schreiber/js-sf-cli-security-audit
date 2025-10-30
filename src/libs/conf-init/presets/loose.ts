import { PermissionRiskLevel } from '../../core/classification-types.js';
import { NamedPermissionsClassification } from '../../core/file-mgmt/schema.js';
import NonePreset from './none.js';

export default class LoosePreset extends NonePreset {
  public constructor() {
    super({
      UseAnyApiClient: PermissionRiskLevel.HIGH,
      CustomizeApplication: PermissionRiskLevel.HIGH,
      ModifyMetadata: PermissionRiskLevel.HIGH,
      AuthorApex: PermissionRiskLevel.HIGH,
      ManageAuthProviders: PermissionRiskLevel.HIGH,
      Packaging2: PermissionRiskLevel.HIGH,
      Packaging2Delete: PermissionRiskLevel.HIGH,
      Packaging2PromoteVersion: PermissionRiskLevel.HIGH,
      InstallPackaging: PermissionRiskLevel.HIGH,
      ViewClientSecret: PermissionRiskLevel.HIGH,
      ManageTwoFactor: PermissionRiskLevel.HIGH,
      ManageRemoteAccess: PermissionRiskLevel.HIGH,
      CanApproveUninstalledApps: PermissionRiskLevel.HIGH,
      ViewSetup: PermissionRiskLevel.MEDIUM,
      ViewAllData: PermissionRiskLevel.MEDIUM,
      ModifyAllData: PermissionRiskLevel.MEDIUM,
      ExportReport: PermissionRiskLevel.MEDIUM,
      EmailMass: PermissionRiskLevel.MEDIUM,
      ApiEnabled: PermissionRiskLevel.LOW,
    });
  }

  public override initDefault(permName: string): NamedPermissionsClassification {
    const basePerm = super.initDefault(permName);
    if (basePerm.classification === PermissionRiskLevel.UNKNOWN) {
      basePerm.classification = PermissionRiskLevel.LOW;
    }
    return basePerm;
  }
}
