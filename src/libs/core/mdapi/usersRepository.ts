import { Connection } from '@salesforce/core';
import { PermissionSet, Profile } from '@jsforce/jsforce-node/lib/api/metadata.js';
import { ACTIVE_USERS_DETAILS_QUERY, buildLoginHistoryQuery } from '../constants.js';
import { User as UserRecord, UserLoginsAggregate } from '../policies/salesforceStandardTypes.js';

export type User = {
  userId: string;
  username: string;
  profileName: string;
  createdDate: number;
  lastLogin?: number;
  logins?: UserLogins[];
};

export type UserPermissions = {
  profileMetadata: Profile;
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
  metadata: PermissionSet;
  /**
   * If permission set is assigned through a group,
   * this is the name of the group.
   */
  groupName?: string;
};

export type ResolveOptions = {
  /**
   * Include aggregated login history
   */
  withLoginHistory: boolean;
  /**
   * When login history is set, the number of days that is searched
   */
  loginHistoryDaysToAnalyse?: number;
};

export default class UsersRepository {
  public constructor(private readonly connection: Connection) {}

  /**
   * Resolves all users from the target org of this repository
   *
   * @param canonicalUsername
   * @param opts
   * @returns
   */
  public async resolveAllUsers(opts?: ResolveOptions): Promise<Map<string, User>> {
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
}
