import { Messages } from '@salesforce/core';
import { NamedPermissionsClassification } from '../../core/file-mgmt/schema.js';
import { PermissionRiskLevel } from '../../core/classification-types.js';
import { Optional } from '../../core/utils.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const descriptions = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policyclassifications');

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
    return rawPerms.map((perm) => ({
      ...this.initDefault(perm.name),
      ...perm,
    }));
  }

  /**
   * Initialises a default classification for a given permission name.
   * This merges pre-configured defaults with available descriptions.
   *
   * @param permName
   * @returns
   */
  public initDefault(permName: string): NamedPermissionsClassification {
    const def = this.userPermissions[permName];
    const hasDescription = descriptions.messages.has(permName);
    return {
      ...def,
      name: permName,
      classification: def?.classification ?? PermissionRiskLevel.UNKNOWN,
      reason: hasDescription ? descriptions.getMessage(permName) : undefined,
    };
  }
}

type UnclassifiedPerm = Optional<NamedPermissionsClassification, 'classification'>;
