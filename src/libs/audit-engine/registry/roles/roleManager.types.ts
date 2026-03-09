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

export type IUserRole = {
  roleName: string;
  isAllowed(perm: Partial<NamedPermissionClassification>): boolean;
};

export type PartialProfileLike = Pick<Profile, 'userPermissions' | 'customPermissions'>;

/**
 * Moves the "name" from the classifications map to object prop
 */
export type NamedPermissionClassification = PermissionClassifications['string'] & { name: string };

export type PermissionsListKey = keyof PartialProfileLike;
