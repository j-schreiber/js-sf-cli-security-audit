import { Messages } from '@salesforce/core';
import { ExtractAuditConfigTypes, RefineError } from '../../file-manager/fileManager.types.js';
import { OrgDescribe } from '../../../../salesforce/index.js';
import { BaseAuditConfigShape } from './auditConfigShape.js';
import { ComposableRolesControl, isPermissionControl, PermissionSetClassifications } from './schema.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'auditShapeValidation');

export const validator = (parseResult: ExtractAuditConfigTypes<typeof BaseAuditConfigShape>): RefineError[] => {
  const errors: RefineError[] = [];
  if (parseResult.controls.roles) {
    if (parseResult.inventory.profiles) {
      errors.push(...validateRoledEntity(parseResult.controls.roles, parseResult.inventory.profiles, 'profiles'));
    }
    if (parseResult.inventory.permissionSets) {
      errors.push(
        ...validateRoledEntity(parseResult.controls.roles, parseResult.inventory.permissionSets, 'permissionSets')
      );
    }
    if (parseResult.inventory.users) {
      errors.push(...validateRoledEntity(parseResult.controls.roles, parseResult.inventory.users, 'users'));
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

export function verifyRoleDefinitions(roles: ComposableRolesControl, orgDescribe: OrgDescribe): RefineError[] {
  const warnings = new Array<RefineError>();
  for (const [roleName, roleDef] of Object.entries(roles)) {
    if (!isPermissionControl(roleDef.permissions) || !roleDef.permissions) {
      continue;
    }
    for (const permissionBlockName of ['userPermissions', 'customPermissions'] as const) {
      const permBlock = roleDef.permissions[permissionBlockName];
      if (!permBlock) {
        continue;
      }
      for (const permProp of ['allowed', 'denied', 'required'] as const) {
        const namedPerms = permBlock[permProp];
        if (namedPerms) {
          for (const permName of namedPerms) {
            if (!orgDescribe.isValid(permName)) {
              warnings.push({
                path: ['Controls', 'Roles', roleName, permissionBlockName, permProp, permName],
                message: messages.getMessage('PermissionDoesNotExistOnOrg'),
              });
            }
          }
        }
      }
    }
  }
  return warnings;
}

function validateRoledEntity(
  roles: ComposableRolesControl,
  entries: PermissionSetClassifications,
  entityName: string
): RefineError[] {
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
