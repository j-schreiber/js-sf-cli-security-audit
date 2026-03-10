import { EventEmitter } from 'node:events';
import { Messages } from '@salesforce/core';
import {
  PermissionClassifications,
  PermissionRiskLevel,
  RoleDefinitions,
  UserPrivilegeLevel,
} from '../shape/schema.js';
import { AuditRunLifecycleBus } from '../../auditRunLifecycle.js';
import {
  NamedPermissionClassification,
  PermissionsListKey,
  ResolvedProfileLike,
  ScanResult,
  UserRoleCompareResult,
} from './roleManager.types.js';
import UserRole, { newRoleFromDefinition, newRoleFromOrdinals } from './userRole.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.enforceClassificationPresets');

type Classifications = {
  userPermissions: PermissionClassifications;
  customPermissions: PermissionClassifications;
};

export default class RoleManager extends EventEmitter {
  private roles: Record<string, UserRole> = {};

  public constructor(private definitions?: RoleDefinitions, private classifications?: Partial<Classifications>) {
    super();
    if (this.definitions) {
      for (const [roleName, roleDef] of Object.entries(this.definitions)) {
        const normalizedName = normalize(roleName);
        if (this.roles[normalizedName]) {
          AuditRunLifecycleBus.emitResolveWarn(
            messages.getMessage('DuplicateRoleAfterNormalization', [
              this.roles[normalizedName].roleName,
              normalizedName,
            ])
          );
        } else {
          this.roles[normalizedName] = newRoleFromDefinition(roleName, roleDef, this.classifications?.userPermissions);
        }
      }
    } else {
      for (const legacyRole of Object.values(UserPrivilegeLevel)) {
        this.roles[normalize(legacyRole)] = newRoleFromOrdinals(legacyRole, this.classifications?.userPermissions);
      }
    }
  }

  /**
   * Scan userPermissions and customPermissions of a profile or permission set and
   * get a unified scan result with violations (risk level not allowed) and warnings
   * (risk level not classified)
   *
   * @param profileLike
   * @param auditRun
   * @param rootIdentifier Optional root identifier for messages to prepend.
   * @returns
   */
  public scanProfileLike(profileLike: ResolvedProfileLike, rootIdentifier?: string[]): ScanResult {
    if (!profileLike.metadata) {
      return { violations: [], warnings: [] };
    }
    const userPermsResult = this.scanPermissions(profileLike, 'userPermissions', rootIdentifier);
    const customPermsResult = this.scanPermissions(profileLike, 'customPermissions', rootIdentifier);
    userPermsResult.violations.push(...customPermsResult.violations);
    userPermsResult.warnings.push(...customPermsResult.warnings);
    return userPermsResult;
  }

  /**
   * Checks if a role allows a certain classifcation level. If the role is
   * not configured or unknown, always returns false.
   *
   * @param roleName
   * @param permission
   * @returns
   */
  public allowsPermission(roleName: string, permission: string): boolean {
    return this.getRole(roleName).isAllowed(permission);
  }

  /**
   * Checks if a given role name is a valid role for the context
   * of the current audit run.
   *
   * @param roleName
   * @returns
   */
  public isValidRole(roleName: string): boolean {
    const normalisedRoleName = normalize(roleName);
    return Boolean(this.roles[normalisedRoleName]);
  }

  /**
   * Compares two roles (both must exist)
   *
   * @param baseRoleName
   * @param compareWithName
   * @returns
   */
  public compare(baseRoleName: string, compareWithName: string): UserRoleCompareResult {
    const baseRole = this.getRole(baseRoleName);
    const otherRole = this.getRole(compareWithName);
    return baseRole.compareWith(otherRole);
  }

  /**
   * Returns the role or throws an error, if role name is invalid.
   *
   * @param roleName
   * @returns
   */
  public getRole(roleName: string): UserRole {
    const normalisedRoleName = normalize(roleName);
    if (this.roles[normalisedRoleName]) {
      return this.roles[normalisedRoleName];
    }
    throw messages.createError('TriedToAccessRoleThatDoesNotExist', [roleName]);
  }

  //          PRIVATE ZONE

  private scanPermissions(
    profile: ResolvedProfileLike,
    permissionListName: PermissionsListKey,
    rootIdentifier?: string[]
  ): ScanResult {
    const result: ScanResult = { warnings: [], violations: [] };
    for (const perm of profile.metadata[permissionListName]) {
      const identifier = rootIdentifier ? [...rootIdentifier, profile.name, perm.name] : [profile.name, perm.name];
      const permClassification = this.resolvePerm(perm.name, permissionListName);
      if (permClassification) {
        if (permClassification.classification === PermissionRiskLevel.BLOCKED) {
          result.violations.push({
            identifier,
            message: messages.getMessage('violations.permission-is-blocked'),
          });
        } else if (!this.allowsPermission(profile.role, permClassification.name)) {
          result.violations.push({
            identifier,
            message: messages.getMessage('violations.classification-preset-mismatch', [
              permClassification.classification,
              profile.role,
            ]),
          });
        } else if (permClassification.classification === PermissionRiskLevel.UNKNOWN) {
          result.warnings.push({
            identifier,
            message: messages.getMessage('warnings.permission-unknown'),
          });
        }
      } else {
        result.warnings.push({
          identifier,
          message: messages.getMessage('warnings.permission-not-classified'),
        });
      }
    }
    return result;
  }

  private resolvePerm(permName: string, listName: PermissionsListKey): NamedPermissionClassification | undefined {
    if (listName === 'userPermissions') {
      return this.resolveUserPerm(permName);
    } else if (listName === 'customPermissions') {
      return this.resolveCustomPerm(permName);
    }
  }

  private resolveUserPerm(permName: string): NamedPermissionClassification | undefined {
    if (this.classifications?.userPermissions) {
      return nameClassification(permName, this.classifications.userPermissions[permName]);
    }
    return undefined;
  }

  private resolveCustomPerm(permName: string): NamedPermissionClassification | undefined {
    if (this.classifications?.customPermissions) {
      return nameClassification(permName, this.classifications.customPermissions[permName]);
    }
    return undefined;
  }
}

function nameClassification(
  permName: string,
  perm?: PermissionClassifications['string']
): NamedPermissionClassification | undefined {
  return perm ? { name: permName, ...perm } : undefined;
}

function normalize(roleName: string): string {
  return roleName.toUpperCase().replaceAll(' ', '_');
}
