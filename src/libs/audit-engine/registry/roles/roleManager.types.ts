import { Profile, ProfileObjectPermissions } from '@jsforce/jsforce-node/lib/api/metadata.js';
import { PolicyRuleViolation, RuleComponentMessage } from '../result.types.js';
import {
  ComposableRolesControl,
  PermissionClassifications,
  ResolvedRoleDefinition,
  PermissionControls,
  ObjectAccessControls,
  ObjectAccessControl,
} from '../shape/schema.js';

export type RoleManagerConfig = {
  controls: {
    roles?: ComposableRolesControl;
    permissions?: PermissionControls;
    objectAccess?: ObjectAccessControls;
  };
  shape: {
    userPermissions?: PermissionClassifications;
    customPermissions?: PermissionClassifications;
  };
};

export type OrgAuditShape = RoleManagerConfig['shape'];
export type OrgAuditControls = RoleManagerConfig['controls'];
export type ComposableRoleDefinition = ComposableRolesControl['string'];

export type DefinitiveRoleDefinition = Required<ResolvedRoleDefinition>;

export type DefinitiveObjectAccessDef = Required<ObjectAccessControl['string']>;

export type ProfileLike = {
  name: string;
  type: 'Profile' | 'PermissionSet';
  metadata?: PartialProfileLike;
};

export type RefinedProfileLike = {
  name: string;
  type: 'Profile' | 'PermissionSet';
  metadata: PartialProfileLike;
};

export type ResolvedProfileLike = ProfileLike & {
  role: string;
};

export type ScanResult = {
  violations: PolicyRuleViolation[];
  warnings: RuleComponentMessage[];
  errors: RuleComponentMessage[];
};

export type UserRoleCompareResult = {
  /**
   * True if the given role is a superset of the other compared role.
   * This means, it contains at least all allowed permissions and
   * fewer denied permissions as the "other role".
   */
  isSuperset: boolean;
  /**
   * List of permissions that are present in "this" role and
   * missing in the compared "other" role.
   */
  missingPermsInOther: string[];
  /**
   * List of permissions that are present in compared "other"
   * role and missing in this role.
   */
  missingPermsInThis: string[];
};

export type IUserRole = {
  roleName: string;
  isAllowed(perm: Partial<NamedPermissionClassification>): boolean;
  compareWith(otherRole: IUserRole): UserRoleCompareResult;
};

export type PartialProfileLike = Pick<Profile, PermissionsListKey | 'objectPermissions'>;

export type TypedPermission = {
  type: PermissionsListKey;
  name: string;
};

/**
 * JsForce does not yet expose "viewAllFields" property. This override augments
 * the standard export to be able to audit for it.
 */
export type ExtendedObjectAccessPermissions = ProfileObjectPermissions & {
  viewAllFields?: boolean | null | undefined;
};

/**
 * Moves the "name" from the classifications map to object prop
 */
export type NamedPermissionClassification = PermissionClassifications['string'] & { name: string };

export type PermissionsListKey = 'userPermissions' | 'customPermissions';

export function isRefinedProfileLike(p: ProfileLike): p is RefinedProfileLike {
  return p.metadata !== undefined;
}
