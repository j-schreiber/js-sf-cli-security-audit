import { PermissionRiskLevel } from '../../core/classification-types.js';
import { NamedPermissionClassification } from '../../core/file-mgmt/schema.js';
import NonePreset from './none.js';

export default class LoosePreset extends NonePreset {
  public constructor() {
    super({
      UseAnyApiClient: PermissionRiskLevel.HIGH,
      BypassMFAForUiLogins: PermissionRiskLevel.HIGH,
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
      ManageUsers: PermissionRiskLevel.HIGH,
      ViewAllForecasts: PermissionRiskLevel.HIGH,
      ResetPasswords: PermissionRiskLevel.HIGH,
      CanInsertFeedSystemFields: PermissionRiskLevel.HIGH,
      ManageHealthCheck: PermissionRiskLevel.HIGH,
      ManageSubscriptions: PermissionRiskLevel.HIGH,
      ViewAllProfiles: PermissionRiskLevel.HIGH,
      ManageExternalConnections: PermissionRiskLevel.HIGH,
      ManageNamedCredentials: PermissionRiskLevel.HIGH,
      CodeBuilderUser: PermissionRiskLevel.HIGH,
      MonitorLoginHistory: PermissionRiskLevel.HIGH,
      ManagePackageLicenses: PermissionRiskLevel.HIGH,
      BulkApiHardDelete: PermissionRiskLevel.HIGH,
      ViewHealthCheck: PermissionRiskLevel.MEDIUM,
      FreezeUsers: PermissionRiskLevel.MEDIUM,
      ManageRoles: PermissionRiskLevel.MEDIUM,
      ViewSetup: PermissionRiskLevel.MEDIUM,
      ViewAllData: PermissionRiskLevel.MEDIUM,
      ModifyAllData: PermissionRiskLevel.MEDIUM,
      ExportReport: PermissionRiskLevel.MEDIUM,
      EmailMass: PermissionRiskLevel.MEDIUM,
      AccessContentBuilder: PermissionRiskLevel.MEDIUM,
      DataExport: PermissionRiskLevel.MEDIUM,
      NewReportBuilder: PermissionRiskLevel.MEDIUM,
      ImportLeads: PermissionRiskLevel.MEDIUM,
      EditBrandTemplates: PermissionRiskLevel.MEDIUM,
      DeleteActivatedContract: PermissionRiskLevel.MEDIUM,
      OverrideForecasts: PermissionRiskLevel.MEDIUM,
      ManageNetworks: PermissionRiskLevel.MEDIUM,
      ViewAllUsers: PermissionRiskLevel.MEDIUM,
      ViewRoles: PermissionRiskLevel.MEDIUM,
      ModerateNetworkUsers: PermissionRiskLevel.MEDIUM,
      EmailAdministration: PermissionRiskLevel.MEDIUM,
      ApiEnabled: PermissionRiskLevel.LOW,
      LightningExperienceUser: PermissionRiskLevel.LOW,
      RunReports: PermissionRiskLevel.LOW,
      ScheduleReports: PermissionRiskLevel.LOW,
      ActivateContract: PermissionRiskLevel.LOW,
      ActivateOrder: PermissionRiskLevel.LOW,
      ViewEncryptedData: PermissionRiskLevel.LOW,
      PasswordNeverExpires: PermissionRiskLevel.LOW,
      ActivitiesAccess: PermissionRiskLevel.LOW,
      ForceTwoFactor: PermissionRiskLevel.LOW,
      ManageQuotas: PermissionRiskLevel.LOW,
      ApproveContract: PermissionRiskLevel.LOW,
    });
  }

  public override initDefault(permName: string): NamedPermissionClassification {
    const basePerm = super.initDefault(permName);
    if (basePerm.classification === PermissionRiskLevel.UNKNOWN) {
      basePerm.classification = PermissionRiskLevel.LOW;
    }
    return basePerm;
  }
}
