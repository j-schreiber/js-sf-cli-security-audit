import { EventEmitter } from 'node:events';
import { Messages } from '@salesforce/core';
import { PermissionClassifications, PermissionRiskLevel, UserPrivilegeLevel } from '../shape/schema.js';
import { AuditRunLifecycleBus } from '../../auditRunLifecycle.js';
import {
  isRefinedProfileLike,
  NamedPermissionClassification,
  PermissionsListKey,
  ProfileLike,
  RefinedProfileLike,
  RoleManagerConfig,
  ScanResult,
  UserRoleCompareResult,
} from './roleManager.types.js';
import UserRole, { newRoleFromDefinition, newRoleFromOrdinals } from './userRole.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.enforceClassificationPresets');

const ObjectAccessKeys = ['allowRead', 'allowCreate', 'allowEdit', 'allowDelete'] as const;

type ProfileLikeRefineResult = {
  role: UserRole | undefined;
  profileLikes: RefinedProfileLike[];
  errors: ScanResult['errors'];
};

export default class RoleManager extends EventEmitter {
  private roles: Record<string, UserRole> = {};

  public constructor(private readonly auditConfig: RoleManagerConfig) {
    super();
    if (this.auditConfig.controls.roles) {
      for (const [roleName] of Object.entries(this.auditConfig.controls.roles)) {
        const normalizedName = normalize(roleName);
        if (this.roles[normalizedName]) {
          AuditRunLifecycleBus.emitResolveWarn(
            messages.getMessage('DuplicateRoleAfterNormalization', [
              this.roles[normalizedName].roleName,
              normalizedName,
            ])
          );
        } else {
          this.roles[normalizedName] = newRoleFromDefinition(roleName, this.auditConfig);
        }
      }
    } else {
      for (const legacyRole of Object.values(UserPrivilegeLevel)) {
        this.roles[normalize(legacyRole)] = newRoleFromOrdinals(legacyRole, this.auditConfig.shape?.userPermissions);
      }
    }
  }

  /**
   * Scan userPermissions and customPermissions of a profile or permission set and
   * get a unified scan result with violations (risk level not allowed) and warnings
   * (risk level not classified)
   *
   * @param role The desired role
   * @param profileLikes List or single instance of profiles to audit
   * @param rootIdentifier Optional root identifier for messages to prepend.
   * @returns
   */
  public scanPermissions(
    role: string,
    profileLikes: ProfileLike[] | ProfileLike,
    identifier: string[] = []
  ): ScanResult {
    const profileLikesInput = Array.isArray(profileLikes) ? profileLikes : [profileLikes];
    const result: ScanResult = { violations: [], warnings: [], errors: [] };
    const refineResult = this.assertProfileLikeIntegrity(role, profileLikesInput, identifier);
    result.errors.push(...refineResult.errors);
    if (refineResult.role && refineResult.profileLikes.length > 0) {
      for (const profileLike of refineResult.profileLikes) {
        const localIdentifier = [...identifier, profileLike.name];
        for (const permKey of ['userPermissions', 'customPermissions'] as const) {
          const { violations, warnings } = this.scanPermissionList(
            refineResult.role,
            profileLike,
            permKey,
            localIdentifier
          );
          result.violations.push(...violations);
          result.warnings.push(...warnings);
        }
      }
    }

    return result;
  }

  /**
   * Scans object permissions of a profile or permission set and compares with
   * the permissions that are allowed by the role.
   *
   * @param profileLike
   * @param rootIdentifier
   * @returns
   */
  public scanObjectAccess(role: string, profileLikes: ProfileLike[], rootIdentifier: string[] = []): ScanResult {
    const result: ScanResult = { violations: [], warnings: [], errors: [] };
    const refineResult = this.assertProfileLikeIntegrity(role, profileLikes, rootIdentifier);
    result.errors.push(...refineResult.errors);
    if (refineResult.role && refineResult.profileLikes.length > 0) {
      for (const profileLike of refineResult.profileLikes) {
        const violations = scanProfileObjectPermissions(refineResult.role, profileLike, [
          ...rootIdentifier,
          profileLike.name,
        ]);
        result.violations.push(...violations);
      }
    }
    return result;
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

  private assertProfileLikeIntegrity(
    role: string,
    profileLikes: ProfileLike[],
    identifier: string[]
  ): ProfileLikeRefineResult {
    const refineResult: ProfileLikeRefineResult = { errors: [], profileLikes: [], role: undefined };
    if (this.isValidRole(role)) {
      refineResult.role = this.getRole(role);
    } else {
      refineResult.errors.push(
        ...profileLikes.map((pl) => ({
          identifier: [...identifier, pl.name],
          message: messages.getMessage('error.failed-to-resolve-role', [role]),
        }))
      );
    }
    for (const pl of profileLikes) {
      if (isRefinedProfileLike(pl)) {
        refineResult.profileLikes.push(pl);
      } else {
        refineResult.errors.push({
          identifier: [...identifier, pl.name],
          message: messages.getMessage('errors.profile-like-has-no-metadata', [pl.type]),
        });
      }
    }
    return refineResult;
  }

  private scanPermissionList(
    role: UserRole,
    profile: RefinedProfileLike,
    permissionType: PermissionsListKey,
    rootIdentifier: string[]
  ): Pick<ScanResult, 'warnings' | 'violations'> {
    const result: Pick<ScanResult, 'warnings' | 'violations'> = { warnings: [], violations: [] };
    for (const perm of profile.metadata[permissionType]) {
      const identifier = [...rootIdentifier, perm.name];
      const permClassification = this.resolvePerm(perm.name, permissionType);
      if (permClassification) {
        if (permClassification.classification === PermissionRiskLevel.BLOCKED) {
          result.violations.push({
            identifier,
            message: messages.getMessage('violations.permission-is-blocked'),
          });
        } else if (!role.isAllowed({ name: permClassification.name, type: permissionType })) {
          result.violations.push({
            identifier,
            message: messages.getMessage('violations.classification-preset-mismatch', [
              permClassification.classification,
              role.roleName,
            ]),
          });
        } else if (permClassification.classification === PermissionRiskLevel.UNKNOWN) {
          result.warnings.push({
            identifier,
            message: messages.getMessage('warnings.permission-unknown'),
          });
        }
      } else if (role.isDenied({ name: perm.name, type: permissionType })) {
        result.violations.push({
          identifier,
          message: messages.getMessage('violations.permission-is-denied', [role.roleName]),
        });
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
    if (this.auditConfig.shape?.userPermissions) {
      return nameClassification(permName, this.auditConfig.shape.userPermissions[permName]);
    }
    return undefined;
  }

  private resolveCustomPerm(permName: string): NamedPermissionClassification | undefined {
    if (this.auditConfig.shape?.customPermissions) {
      return nameClassification(permName, this.auditConfig.shape.customPermissions[permName]);
    }
    return undefined;
  }
}

function scanProfileObjectPermissions(
  role: UserRole,
  profileLike: RefinedProfileLike,
  identifier: string[]
): ScanResult['violations'] {
  const violations: ScanResult['violations'] = [];
  for (const objectAccess of profileLike.metadata.objectPermissions ?? []) {
    for (const accessType of ObjectAccessKeys) {
      if (objectAccess[accessType] && !role.allowsObjectAccess(objectAccess.object, accessType)) {
        violations.push({
          identifier: [...identifier, objectAccess.object, accessType],
          message: messages.getMessage('violations.object-access-denied', [role.roleName]),
        });
      }
    }
  }
  return violations;
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
