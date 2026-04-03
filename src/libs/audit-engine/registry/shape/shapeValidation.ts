import { Messages } from '@salesforce/core';
import { ExtractAuditConfigTypes, RefineError } from '../../file-manager/fileManager.types.js';
import { OrgDescribe } from '../../../../salesforce/index.js';
import { BaseAuditConfigShape } from './auditConfigShape.js';
import { RoleDefinitions, RoledEntityMap } from './schema.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'auditShapeValidation');

export const validator = (parseResult: ExtractAuditConfigTypes<typeof BaseAuditConfigShape>): RefineError[] => {
  const errors: RefineError[] = [];
  if (parseResult.definitions.roles) {
    if (parseResult.classifications.profiles) {
      errors.push(
        ...validateRoledEntity(parseResult.definitions.roles, parseResult.classifications.profiles.profiles, 'profiles')
      );
    }
    if (parseResult.classifications.permissionSets) {
      errors.push(
        ...validateRoledEntity(
          parseResult.definitions.roles,
          parseResult.classifications.permissionSets.permissionSets,
          'permissionSets'
        )
      );
    }
    if (parseResult.classifications.users) {
      errors.push(
        ...validateRoledEntity(parseResult.definitions.roles, parseResult.classifications.users.users, 'users')
      );
    }
  }
  if (!parseResult.policies || Object.keys(parseResult.policies).length === 0) {
    errors.push({
      message: messages.getMessage('NoAuditConfigFound'),
      path: ['policies'],
    });
  }
  return errors;
};

export function verifyRoleDefinitions(roles: RoleDefinitions, orgDescribe: OrgDescribe): RefineError[] {
  const PermissionKeys = ['allowedPermissions', 'deniedPermissions'] as const;
  const warnings = new Array<RefineError>();
  for (const [roleName, roleDef] of Object.entries(roles)) {
    for (const permProp of PermissionKeys) {
      const namedPerms = roleDef[permProp];
      if (namedPerms) {
        for (const permName of namedPerms) {
          if (!orgDescribe.isValid(permName)) {
            warnings.push({
              path: ['Controls', 'Roles', roleName, permProp, permName],
              message: messages.getMessage('PermissionDoesNotExistOnOrg'),
            });
          }
        }
      }
    }
  }
  return warnings;
}

function validateRoledEntity(roles: RoleDefinitions, entries: RoledEntityMap, entityName: string): RefineError[] {
  const errors: RefineError[] = [];
  for (const [identifier, entity] of Object.entries(entries)) {
    if (!roles[entity.role]) {
      errors.push({
        message: messages.getMessage('RoleNotInDefinition', [entity.role]),
        path: [entityName, identifier],
      });
    }
  }
  return errors;
}
