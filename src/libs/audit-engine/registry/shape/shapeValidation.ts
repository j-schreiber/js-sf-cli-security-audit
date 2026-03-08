import { Messages } from '@salesforce/core';
import { ExtractAuditConfigTypes, RefineError } from '../../file-manager/fileManager.types.js';
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
