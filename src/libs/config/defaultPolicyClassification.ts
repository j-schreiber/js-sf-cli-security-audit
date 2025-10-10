import { Messages } from '@salesforce/core';
import { PolicyRiskLevel } from '../policies/types.js';
import { PermissionsClassification } from '../policies/schema.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policyclassifications');

export const DEFAULT_CLASSIFICATIONS: Record<string, PermissionsClassification> = {
  CustomizeApplication: {
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
