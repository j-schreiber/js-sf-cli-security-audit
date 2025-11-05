import { PermissionRiskLevel } from '../../core/classification-types.js';
import { NamedPermissionsClassification } from '../../core/file-mgmt/schema.js';
import NonePreset from './none.js';

export default class LoosePreset extends NonePreset {
  public constructor() {
    super({
      UseAnyApiClient: PermissionRiskLevel.HIGH,
      ExternalClientAppAdmin: PermissionRiskLevel.HIGH,
      ManageSandboxes: PermissionRiskLevel.HIGH,
      ManageDevSandboxes: PermissionRiskLevel.HIGH,
      CustomizeApplication: PermissionRiskLevel.HIGH,
      ModifyMetadata: PermissionRiskLevel.HIGH,
      AuthorApex: PermissionRiskLevel.HIGH,
      DebugApex: PermissionRiskLevel.HIGH,
      ManageAuthProviders: PermissionRiskLevel.HIGH,
      Packaging2: PermissionRiskLevel.HIGH,
      Packaging2Delete: PermissionRiskLevel.HIGH,
      Packaging2PromoteVersion: PermissionRiskLevel.HIGH,
      InstallPackaging: PermissionRiskLevel.HIGH,
      ViewClientSecret: PermissionRiskLevel.HIGH,
      ManageTwoFactor: PermissionRiskLevel.HIGH,
      ManageRemoteAccess: PermissionRiskLevel.HIGH,
      CanApproveUninstalledApps: PermissionRiskLevel.HIGH,
      AssignPermissionSets: PermissionRiskLevel.HIGH,
      ManageIpAddresses: PermissionRiskLevel.HIGH,
      ManageSharing: PermissionRiskLevel.HIGH,
      ManageInternalUsers: PermissionRiskLevel.HIGH,
      ManagePasswordPolicies: PermissionRiskLevel.HIGH,
      ManageLoginAccessPolicies: PermissionRiskLevel.HIGH,
      ManageCustomPermissions: PermissionRiskLevel.HIGH,
      ManageCertificates: PermissionRiskLevel.HIGH,
      FreezeUsers: PermissionRiskLevel.MEDIUM,
      ManageRoles: PermissionRiskLevel.MEDIUM,
      ViewSetup: PermissionRiskLevel.MEDIUM,
      ViewAllData: PermissionRiskLevel.MEDIUM,
      ModifyAllData: PermissionRiskLevel.MEDIUM,
      ExportReport: PermissionRiskLevel.MEDIUM,
      EmailMass: PermissionRiskLevel.MEDIUM,
      AccessContentBuilder: PermissionRiskLevel.MEDIUM,
      ApiEnabled: PermissionRiskLevel.LOW,
      LightningExperienceUser: PermissionRiskLevel.LOW,
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
