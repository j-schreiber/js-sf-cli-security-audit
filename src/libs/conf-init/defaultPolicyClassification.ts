import { Messages } from '@salesforce/core';
import { PermissionsClassification } from '../core/file-mgmt/schema.js';
import { PermissionRiskLevel } from '../core/classification-types.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policyclassifications');

export const DEFAULT_CLASSIFICATIONS: Record<string, PermissionsClassification> = {
  CustomizeApplication: {
    classification: PermissionRiskLevel.CRITICAL,
    reason: messages.getMessage('CustomizeApplication'),
  },
  ModifyMetadata: {
    classification: PermissionRiskLevel.CRITICAL,
    reason: messages.getMessage('CustomizeApplication'),
  },
  ViewSetup: {
    classification: PermissionRiskLevel.HIGH,
    reason: messages.getMessage('ViewSetup'),
  },
  AuthorApex: {
    classification: PermissionRiskLevel.CRITICAL,
    reason: messages.getMessage('AuthorApex'),
  },
  ManageAuthProviders: {
    classification: PermissionRiskLevel.CRITICAL,
    reason: messages.getMessage('ManageAuthProviders'),
  },
  Packaging2: {
    classification: PermissionRiskLevel.CRITICAL,
    reason: messages.getMessage('Packaging'),
  },
  Packaging2Delete: {
    classification: PermissionRiskLevel.CRITICAL,
    reason: messages.getMessage('Packaging'),
  },
  Packaging2PromoteVersion: {
    classification: PermissionRiskLevel.CRITICAL,
    reason: messages.getMessage('Packaging'),
  },
  InstallPackaging: {
    classification: PermissionRiskLevel.CRITICAL,
    reason: messages.getMessage('Packaging'),
  },
  ApiEnabled: {
    classification: PermissionRiskLevel.HIGH,
    reason: messages.getMessage('ApiEnabled'),
  },
  ViewAllData: {
    classification: PermissionRiskLevel.HIGH,
    reason: messages.getMessage('ViewAllData'),
  },
  ModifyAllData: {
    classification: PermissionRiskLevel.HIGH,
    reason: messages.getMessage('ViewAllData'),
  },
  ManageTwoFactor: {
    classification: PermissionRiskLevel.HIGH,
    reason: messages.getMessage('ManageTwoFactor'),
  },
  CanApproveUninstalledApps: {
    classification: PermissionRiskLevel.HIGH,
    reason: messages.getMessage('CanApproveUninstalledApps'),
  },
};
