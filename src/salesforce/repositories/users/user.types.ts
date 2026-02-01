import z from 'zod';
import { PermissionSet, Profile } from '@jsforce/jsforce-node/lib/api/metadata.js';

export type User = {
  userId: string;
  username: string;
  profileName: string;
  createdDate: number;
  isActive: boolean;
  lastLogin?: number;
  logins?: UserLogins[];
  assignments?: PermissionSetAssignment[];
  profileMetadata?: Profile;
};

export type UserPermissions = {
  profileMetadata?: Profile;
  assignedPermissionsets: PermissionSetAssignment[];
};

export type UserLogins = {
  loginType: string;
  application: string;
  loginCount: number;
  lastLogin: number;
};

export type PermissionSetAssignment = {
  /**
   * Developer name of the permission set
   */
  permissionSetIdentifier: string;
  /**
   * How user got this permission set assigned
   */
  permissionSetSource: 'direct' | 'group';
  /**
   * Metadata of the permission set
   */
  metadata?: PermissionSet;
  /**
   * If permission set is assigned through a group,
   * this is the name of the group.
   */
  groupName?: string;
};

export const ResolveUsersOptionsSchema = z.object({
  /** Resolve users with login history */
  withLoginHistory: z.boolean().default(false),
  /** Length of login history. Has no effect, if login history is false */
  loginHistoryDaysToAnalyse: z.number().optional(),
  /** Include profile and assigned permission sets */
  withPermissions: z.boolean().default(false),
  /** Adds metadata to permissions. Has no effect, if withPermissions is false */
  withPermissionsMetadata: z.boolean().default(false),
});

export type ResolveUsersOptions = z.infer<typeof ResolveUsersOptionsSchema>;

export type ResolvePermissionsOptions = {
  /**
   * Resolve permission set and profile metadata
   */
  withMetadata: boolean;
};
