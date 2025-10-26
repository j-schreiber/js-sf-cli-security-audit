import { Messages } from '@salesforce/core';
import { NamedPermissionsClassification } from '../../core/file-mgmt/schema.js';
import { PermissionRiskLevel } from '../../core/classification-types.js';
import { Optional } from '../../core/utils.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policyclassifications');

export type Preset = {
  classifyUserPermissions(rawPerms: UnclassifiedPerm[]): NamedPermissionsClassification[];
};

/**
 * A "blank" preset that is extended by all other presets
 * and initialises classification descriptions
 */
export default class NonePreset implements Preset {
  protected userPermissions: Record<string, Partial<NamedPermissionsClassification>>;

  public constructor(userPerms?: Record<string, Partial<NamedPermissionsClassification>>) {
    this.userPermissions = {};
    Object.entries(USER_PERM_DESCRIPTIONS).forEach(([name, description]) => {
      if (this.userPermissions[name]) {
        this.userPermissions[name].reason = description;
      } else {
        this.userPermissions[name] = { reason: description };
      }
    });
    if (userPerms) {
      Object.entries(userPerms).forEach(([name, def]) => {
        if (this.userPermissions[name]) {
          this.userPermissions[name].classification = def.classification;
        } else {
          this.userPermissions[name] = def;
        }
      });
    }
  }

  /**
   * Finalises permissions for all unclassified user perms that are set
   * in this preset.
   *
   * @param perms
   */
  public classifyUserPermissions(rawPerms: UnclassifiedPerm[]): NamedPermissionsClassification[] {
    return rawPerms.map((perm) => {
      const defaultDef = this.userPermissions[perm.name];
      if (defaultDef) {
        return {
          name: perm.name,
          label: perm.label,
          classification: perm.classification ?? defaultDef.classification ?? PermissionRiskLevel.UNKNOWN,
          reason: perm.reason ?? defaultDef.reason,
        };
      } else {
        return {
          ...perm,
          classification: PermissionRiskLevel.UNKNOWN,
        };
      }
    });
  }
}

const USER_PERM_DESCRIPTIONS = {
  CustomizeApplication: messages.getMessage('CustomizeApplication'),
  ModifyMetadata: messages.getMessage('CustomizeApplication'),
  ViewSetup: messages.getMessage('ViewSetup'),
  AuthorApex: messages.getMessage('AuthorApex'),
  ManageAuthProviders: messages.getMessage('ManageAuthProviders'),
  Packaging2: messages.getMessage('Packaging'),
  Packaging2Delete: messages.getMessage('Packaging'),
  Packaging2PromoteVersion: messages.getMessage('Packaging'),
  InstallPackaging: messages.getMessage('Packaging'),
  ApiEnabled: messages.getMessage('ApiEnabled'),
  ViewAllData: messages.getMessage('ViewAllData'),
  ModifyAllData: messages.getMessage('ViewAllData'),
  ManageTwoFactor: messages.getMessage('ManageTwoFactor'),
  CanApproveUninstalledApps: messages.getMessage('CanApproveUninstalledApps'),
  UseAnyApiClient: messages.getMessage('UseAnyApiClient'),
  ViewClientSecret: messages.getMessage('ViewClientSecret'),
  ExportResport: messages.getMessage('ExportReport'),
};

type UnclassifiedPerm = Optional<NamedPermissionsClassification, 'classification'>;
