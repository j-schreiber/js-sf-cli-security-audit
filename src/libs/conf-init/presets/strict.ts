import { PermissionRiskLevel } from '../../core/classification-types.js';
import NonePreset from './none.js';

export default class StrictPreset extends NonePreset {
  public constructor() {
    super({
      UseAnyApiClient: {
        classification: PermissionRiskLevel.BLOCKED,
      },
      CustomizeApplication: {
        classification: PermissionRiskLevel.CRITICAL,
      },
      ModifyMetadata: {
        classification: PermissionRiskLevel.CRITICAL,
      },
      AuthorApex: {
        classification: PermissionRiskLevel.CRITICAL,
      },
      ManageAuthProviders: {
        classification: PermissionRiskLevel.CRITICAL,
      },
      Packaging2: {
        classification: PermissionRiskLevel.CRITICAL,
      },
      Packaging2Delete: {
        classification: PermissionRiskLevel.CRITICAL,
      },
      Packaging2PromoteVersion: {
        classification: PermissionRiskLevel.CRITICAL,
      },
      InstallPackaging: {
        classification: PermissionRiskLevel.CRITICAL,
      },
      ViewClientSecret: {
        classification: PermissionRiskLevel.CRITICAL,
      },
      ExportReport: {
        classification: PermissionRiskLevel.HIGH,
      },
      ViewSetup: {
        classification: PermissionRiskLevel.HIGH,
      },
      ApiEnabled: {
        classification: PermissionRiskLevel.HIGH,
      },
      ViewAllData: {
        classification: PermissionRiskLevel.HIGH,
      },
      ModifyAllData: {
        classification: PermissionRiskLevel.HIGH,
      },
      ManageTwoFactor: {
        classification: PermissionRiskLevel.HIGH,
      },
      CanApproveUninstalledApps: {
        classification: PermissionRiskLevel.HIGH,
      },
      EmailMass: {
        classification: PermissionRiskLevel.MEDIUM,
      },
    });
  }
}
