import { EventEmitter } from 'node:events';
import { Messages } from '@salesforce/core';
import {
  PermissionClassifications,
  PermissionRiskLevel,
  RoleDefinitions,
  UserPrivilegeLevel,
} from '../shape/schema.js';
import { AuditRunLifecycleBus } from '../../auditRunLifecycle.js';
import { AuditRunConfig } from '../definitions.js';
import {
  IUserRole,
  NamedPermissionClassification,
  PermissionsListKey,
  ResolvedProfileLike,
  ScanResult,
  UserRoleCompareResult,
} from './roleManager.types.js';
import LegacyRole from './legacyRole.js';
import ModernRole from './modernRole.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.enforceClassificationPresets');

export default class RoleManager extends EventEmitter {
  private roles: Record<string, IUserRole> = {};

  public constructor(private definitions?: RoleDefinitions) {
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
          this.roles[normalizedName] = new ModernRole(roleName, roleDef);
        }
      }
    } else {
      for (const legacyRole of Object.keys(UserPrivilegeLevel)) {
        this.roles[legacyRole] = new LegacyRole(legacyRole);
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
  public scanProfileLike(
    profileLike: ResolvedProfileLike,
    auditRun: AuditRunConfig,
    rootIdentifier?: string[]
  ): ScanResult {
    if (!profileLike.metadata) {
      return { violations: [], warnings: [] };
    }
    const userPermsResult = this.scanPermissions(profileLike, 'userPermissions', auditRun, rootIdentifier);
    const customPermsResult = this.scanPermissions(profileLike, 'customPermissions', auditRun, rootIdentifier);
    userPermsResult.violations.push(...customPermsResult.violations);
    userPermsResult.warnings.push(...customPermsResult.warnings);
    return userPermsResult;
  }

  public scanPermissions(
    profile: ResolvedProfileLike,
    permissionListName: PermissionsListKey,
    auditRun: AuditRunConfig,
    rootIdentifier?: string[]
  ): ScanResult {
    const result: ScanResult = { warnings: [], violations: [] };
    for (const perm of profile.metadata[permissionListName]) {
      const identifier = rootIdentifier ? [...rootIdentifier, profile.name, perm.name] : [profile.name, perm.name];
      const permClassification = resolvePerm(perm.name, auditRun, permissionListName);
      if (permClassification) {
        if (permClassification.classification === PermissionRiskLevel.BLOCKED) {
          result.violations.push({
            identifier,
            message: messages.getMessage('violations.permission-is-blocked'),
          });
        } else if (!this.allowsPermission(profile.role, permClassification)) {
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

  /**
   * Checks if a role allows a certain classifcation level. If the role is
   * not configured or unknown, always returns false.
   *
   * @param roleName
   * @param permission
   * @returns
   */
  public allowsPermission(roleName: string, permission: Partial<NamedPermissionClassification>): boolean {
    if (this.isValidRole(roleName)) {
      return this.roles[normalize(roleName)].isAllowed(permission);
    }
    return false;
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
  public getRole(roleName: string): IUserRole {
    const normalisedRoleName = normalize(roleName);
    if (this.roles[normalisedRoleName]) {
      return this.roles[normalisedRoleName];
    }
    throw messages.createError('TriedToAccessRoleThatDoesNotExist', [roleName]);
  }
}

function resolvePerm(
  permName: string,
  auditRun: AuditRunConfig,
  type: PermissionsListKey
): NamedPermissionClassification | undefined {
  return nameClassification(permName, auditRun.classifications[type]?.permissions[permName]);
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
