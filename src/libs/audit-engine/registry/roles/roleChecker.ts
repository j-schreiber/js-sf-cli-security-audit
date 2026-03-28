import { Messages } from '@salesforce/core';
import { OrgDescribe } from '../../../../salesforce/index.js';
import { RoleDefinitions } from '../shape/schema.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.enforceClassificationPresets');

const PermissionKeys = ['allowedPermissions', 'deniedPermissions'] as const;

/**
 * Validates a role definition against an org describe
 */
export default class RoleChecker {
  public constructor(private readonly org: OrgDescribe, private definitions: RoleDefinitions = {}) {}

  /**
   * Validates all named permissions in the definition
   * against the target org and returns formatted warnings
   *
   * @param roleDef
   */
  public checkRoleDefinitionAgainstOrg(roleName: string): string[] {
    const roleDef = this.definitions[roleName] ?? {};
    const warnings = [];
    for (const permProp of PermissionKeys) {
      const namedPerms = roleDef[permProp];
      if (namedPerms) {
        for (const permName of namedPerms) {
          if (!this.org.isValid(permName)) {
            warnings.push(messages.getMessage('warnings.role-permission-invalid-for-org', [permName, permProp]));
          }
        }
      }
    }
    return warnings;
  }
}
