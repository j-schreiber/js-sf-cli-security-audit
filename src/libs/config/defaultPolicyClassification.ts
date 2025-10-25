import { Messages } from '@salesforce/core';
import { PolicyRiskLevel } from '../policies/types.js';
import { PermissionsClassification } from '../core/file-mgmt/schema.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policyclassifications');

export const DEFAULT_CLASSIFICATIONS: Record<string, PermissionsClassification> = {
  CustomizeApplication: {
    classification: PolicyRiskLevel.CRITICAL,
    reason: messages.getMessage('CustomizeApplication'),
  },
  ModifyMetadata: {
    classification: PolicyRiskLevel.CRITICAL,
    reason: messages.getMessage('CustomizeApplication'),
  },
  ViewSetup: {
    classification: PolicyRiskLevel.HIGH,
    reason: messages.getMessage('ViewSetup'),
  },
  AuthorApex: {
    classification: PolicyRiskLevel.CRITICAL,
    reason: messages.getMessage('AuthorApex'),
  },
  ManageAuthProviders: {
    classification: PolicyRiskLevel.CRITICAL,
    reason: messages.getMessage('ManageAuthProviders'),
  },
  Packaging2: {
    classification: PolicyRiskLevel.CRITICAL,
    reason: messages.getMessage('Packaging'),
  },
  Packaging2Delete: {
    classification: PolicyRiskLevel.CRITICAL,
    reason: messages.getMessage('Packaging'),
  },
  Packaging2PromoteVersion: {
    classification: PolicyRiskLevel.CRITICAL,
    reason: messages.getMessage('Packaging'),
  },
  InstallPackaging: {
    classification: PolicyRiskLevel.CRITICAL,
    reason: messages.getMessage('Packaging'),
  },
  ApiEnabled: {
    classification: PolicyRiskLevel.HIGH,
    reason: messages.getMessage('ApiEnabled'),
  },
  ViewAllData: {
    classification: PolicyRiskLevel.HIGH,
    reason: messages.getMessage('ViewAllData'),
  },
  ModifyAllData: {
    classification: PolicyRiskLevel.HIGH,
    reason: messages.getMessage('ViewAllData'),
  },
  ManageTwoFactor: {
    classification: PolicyRiskLevel.HIGH,
    reason: messages.getMessage('ManageTwoFactor'),
  },
  CanApproveUninstalledApps: {
    classification: PolicyRiskLevel.HIGH,
    reason: messages.getMessage('CanApproveUninstalledApps'),
  },
};
