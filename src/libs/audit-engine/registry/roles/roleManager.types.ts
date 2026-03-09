import { Profile } from '@jsforce/jsforce-node/lib/api/metadata.js';
import { PolicyRuleViolation, RuleComponentMessage } from '../result.types.js';
import { PermissionClassifications } from '../shape/schema.js';

export type ResolvedProfileLike = {
  name: string;
  role: string;
  metadata: PartialProfileLike;
};

export type ScanResult = {
  violations: PolicyRuleViolation[];
  warnings: RuleComponentMessage[];
};

export type UserRoleCompareResult = {
  /**
   * True if the given role is a superset of the other compared role.
   * This means, it contains at least all allowed permissions and
   * fewer denied permissions as the "other role".
   */
  isSuperset: boolean;
};

export type IUserRole = {
  roleName: string;
  isAllowed(perm: Partial<NamedPermissionClassification>): boolean;
  compareWith(otherRole: IUserRole): UserRoleCompareResult;
};

export type PartialProfileLike = Pick<Profile, 'userPermissions' | 'customPermissions'>;

/**
 * Moves the "name" from the classifications map to object prop
 */
export type NamedPermissionClassification = PermissionClassifications['string'] & { name: string };

export type PermissionsListKey = keyof PartialProfileLike;
