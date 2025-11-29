import { Connection } from '@salesforce/core';
import { PermissionSet, Profile } from '@jsforce/jsforce-node/lib/api/metadata.js';
import { ACTIVE_USERS_DETAILS_QUERY, buildLoginHistoryQuery, buildPermsetAssignmentsQuery } from '../constants.js';
import {
  User as UserRecord,
  UserLoginsAggregate,
  PermissionSetAssignment as PermissionSetAssignmentRecord,
} from '../policies/salesforceStandardTypes.js';
import { isNullish } from '../utils.js';
import MDAPI from './mdapiRetriever.js';

export type User = {
  userId: string;
  username: string;
  profileName: string;
  createdDate: number;
  lastLogin?: number;
  logins?: UserLogins[];
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

export type ResolveUsersOptions = {
  /**
   * Include aggregated login history
   */
  withLoginHistory: boolean;
  /**
   * When login history is set, the number of days that is searched
   */
  loginHistoryDaysToAnalyse?: number;
};

export type ResolvePermissionsOptions = {
  /**
   * Resolve permission set and profile metadata
   */
  withMetadata: boolean;
};

type PartialAssignments = Array<Omit<PermissionSetAssignment, 'metadata'>>;

type PartialAssignmentsResult = {
  assignments: Map<string, PartialAssignments>;
  permSetNames: string[];
};

export default class UsersRepository {
  private readonly mdapiRepo;

  public constructor(private readonly connection: Connection) {
    this.mdapiRepo = MDAPI.create(this.connection);
  }

  /**
   * Resolves all users from the target org of this repository
   *
   * @param opts
   * @returns
   */
  public async resolveAllUsers(opts?: ResolveUsersOptions): Promise<Map<string, User>> {
    const result: Map<string, User> = new Map<string, User>();
    const allUsersOnOrg = await this.connection.query<UserRecord>(ACTIVE_USERS_DETAILS_QUERY);
    for (const user of allUsersOnOrg.records) {
      const usr = {
        userId: user.Id!,
        username: user.Username,
        lastLogin: user.LastLoginDate ? Date.parse(user.LastLoginDate) : undefined,
        createdDate: Date.parse(user.CreatedDate),
        profileName: user.Profile.Name,
      };
      result.set(user.Username, usr);
    }
    if (opts?.withLoginHistory) {
      const userLogins = await this.resolveLogins(opts.loginHistoryDaysToAnalyse);
      for (const user of result.values()) {
        if (userLogins.has(user.userId)) {
          user.logins = userLogins.get(user.userId);
        } else {
          user.logins = [];
        }
      }
    }
    return result;
  }

  /**
   * Resolves permission-granting entities (profiles and permission sets)
   * for a list of users.
   *
   * @param userIds Users to be resolved
   * @returns Map of permissions organized by user id
   */
  public async resolveUserPermissions(
    users: User[],
    opts?: ResolvePermissionsOptions
  ): Promise<Map<string, UserPermissions>> {
    const result = new Map<string, UserPermissions>();
    const permsets = await this.resolvePermissionSetAssignments(
      users.map((usr) => usr.userId),
      opts
    );
    const profiles = opts?.withMetadata
      ? await this.mdapiRepo.resolve('Profile', uniqueProfileNames(Object.values(users)))
      : {};
    for (const user of users) {
      result.set(user.userId, {
        assignedPermissionsets: permsets.get(user.userId) ?? [],
        profileMetadata: profiles[user.profileName],
      });
    }
    return result;
  }

  /**
   * Resolves all permission set assignments for the user with metadata of the
   * permission set. If the user has no assignments, an empty list is returned.
   *
   * @param userIds
   * @returns
   */
  public async resolvePermissionSetAssignments(
    userIds: string[],
    opts?: ResolvePermissionsOptions
  ): Promise<Map<string, PermissionSetAssignment[]>> {
    const result = new Map<string, PermissionSetAssignment[]>();
    const { assignments, permSetNames } = await this.fetchAssignments(userIds);
    const permsets = opts?.withMetadata ? await this.mdapiRepo.resolve('PermissionSet', permSetNames) : {};
    for (const userId of userIds) {
      result.set(
        userId,
        assignments.get(userId)
          ? assignments.get(userId)!.map((ass) => ({
              ...ass,
              metadata: permsets[ass.permissionSetIdentifier],
            }))
          : []
      );
    }
    return result;
  }

  private async resolveLogins(daysToAnalyse?: number): Promise<Map<string, UserLogins[]>> {
    const loginHistory = await this.connection.query<UserLoginsAggregate>(buildLoginHistoryQuery(daysToAnalyse));
    const partialUsers = new Map<string, UserLogins[]>();
    for (const loginHistoryRow of loginHistory.records) {
      if (!partialUsers.has(loginHistoryRow.UserId)) {
        partialUsers.set(loginHistoryRow.UserId, []);
      }
      partialUsers.get(loginHistoryRow.UserId)!.push({
        loginType: loginHistoryRow.LoginType,
        loginCount: loginHistoryRow.LoginCount,
        application: loginHistoryRow.Application,
        lastLogin: Date.parse(loginHistoryRow.LastLogin),
      });
    }
    return partialUsers;
  }

  private async fetchAssignments(userIds: string[]): Promise<PartialAssignmentsResult> {
    const assignments = new Map<string, PartialAssignments>();
    const uniquePermSets = new Set<string>();
    const rawAssignment = await this.connection.query<PermissionSetAssignmentRecord>(
      buildPermsetAssignmentsQuery(userIds)
    );
    for (const assignment of rawAssignment.records) {
      if (isNullish(assignments.get(assignment.AssigneeId))) {
        assignments.set(assignment.AssigneeId, []);
      }
      assignments.get(assignment.AssigneeId)!.push({
        permissionSetIdentifier: assignment.PermissionSet.Name,
        permissionSetSource: assignment.PermissionSetGroupId ? 'group' : 'direct',
        groupName: assignment.PermissionSetGroup?.DeveloperName,
      });
      uniquePermSets.add(assignment.PermissionSet.Name);
    }
    return { assignments, permSetNames: Array.from(uniquePermSets) };
  }
}

function uniqueProfileNames(users: User[]): string[] {
  const uniqueProfiles = new Set<string>();
  for (const usr of users) {
    uniqueProfiles.add(usr.profileName);
  }
  return Array.from(uniqueProfiles);
}
