import { Messages } from '@salesforce/core';
import { ExtractAuditConfigTypes, RefineError } from '../../file-manager/fileManager.types.js';
import { OrgDescribe } from '../../../../salesforce/index.js';
import { BaseAuditConfigShape } from './auditConfigShape.js';
import { ComposableRolesControl, PermissionSetClassifications, ResolvedRoleDefinition } from './schema.js';

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
    const defaultRole = parseResult.policies.users?.options.defaultRoleForMissingUsers;
    const defaultRoleExistsAndIsValid =
      defaultRole !== undefined && parseResult.controls.roles[defaultRole] !== undefined;
    if (defaultRole && !defaultRoleExistsAndIsValid) {
      errors.push({
        message: messages.getMessage('DefaultRoleForMissingUsersDoesNotExist', [defaultRole]),
        path: ['policies', 'users', 'options', 'defaultRoleForMissingUsers'],
      });
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

export async function verifyRoleDefinitions(
  roles: Record<string, ResolvedRoleDefinition>,
  orgDescribe: OrgDescribe
): Promise<RefineError[]> {
  const warnings = new Array<RefineError>();
  const objectNames: string[] = [];
  for (const [roleName, roleDef] of Object.entries(roles)) {
    if (roleDef.objectAccess) {
      objectNames.push(...Object.keys(roleDef.objectAccess));
    }
    if (roleDef.permissions) {
      for (const permissionBlockName of [
        { listName: 'userPermissions', isValid: (permName: string) => orgDescribe.isValid(permName) },
        { listName: 'customPermissions', isValid: (permName: string) => orgDescribe.isValidCustomPerm(permName) },
      ] as const) {
        const permBlock = roleDef.permissions[permissionBlockName.listName];
        if (!permBlock) {
          continue;
        }
        for (const permProp of ['allowed', 'denied', 'required'] as const) {
          const namedPerms = permBlock[permProp];
          if (namedPerms) {
            for (const permName of namedPerms) {
              if (!permissionBlockName.isValid(permName)) {
                warnings.push({
                  path: ['Controls', 'Roles', roleName, permissionBlockName.listName, permProp, permName],
                  message: messages.getMessage('PermissionDoesNotExistOnOrg'),
                });
              }
            }
          }
        }
      }
    }
  }
  const describes = await orgDescribe.describeSObjects(objectNames);
  for (const [roleName, roleDef] of Object.entries(roles)) {
    if (roleDef.objectAccess) {
      for (const objectName of Object.keys(roleDef.objectAccess)) {
        if (!describes.describes[objectName.toLowerCase()]) {
          warnings.push({
            path: ['Controls', 'Roles', roleName, 'objectAccess', objectName],
            message: messages.getMessage('ObjectDoesNotExistOnOrg'),
          });
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
