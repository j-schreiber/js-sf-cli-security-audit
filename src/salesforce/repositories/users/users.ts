import { Connection } from '@salesforce/core';
import { Record } from '@jsforce/jsforce-node';
import { isNullish } from '../../../utils.js';
import MDAPI from '../../mdapi/mdapi.js';
import {
  PermissionSetAssignment,
  ResolveUsersOptions,
  ResolveUsersOptionsSchema,
  User,
  UserLogins,
} from './user.types.js';
import { ACTIVE_USERS_DETAILS_QUERY, buildLoginHistoryQuery, buildPermsetAssignmentsQuery } from './queries.js';

export default class Users {
  private readonly mdapiRepo: MDAPI;

  public constructor(private readonly connection: Connection) {
    this.mdapiRepo = MDAPI.create(this.connection);
  }

  /**
   * Resolve all users from the target connection. Options controls
   * additional properties that are resolved.
   *
   * @param opts
   * @returns
   */
  public async resolve(opts?: Partial<ResolveUsersOptions>): Promise<Map<string, User>> {
    const definitiveOpts = ResolveUsersOptionsSchema.parse(opts ?? {});
    const result: Map<string, User> = new Map<string, User>();
    const allUsersOnOrg = await this.connection.query<SfUser>(ACTIVE_USERS_DETAILS_QUERY);
    for (const user of allUsersOnOrg.records) {
      const usr = {
        userId: user.Id!,
        username: user.Username,
        lastLogin: user.LastLoginDate ? Date.parse(user.LastLoginDate) : undefined,
        isActive: Boolean(user.IsActive),
        createdDate: Date.parse(user.CreatedDate),
        profileName: user.Profile.Name,
      };
      result.set(user.Username, usr);
    }
    if (definitiveOpts.withLoginHistory) {
      await this.resolveLogins(result, definitiveOpts.loginHistoryDaysToAnalyse);
    }
    if (definitiveOpts.withPermissions) {
      await this.resolvePermissions(result, definitiveOpts.withPermissionsMetadata);
    }
    return result;
  }

  //        PRIVATE ZONE

  private async resolveLogins(users: Map<string, User>, daysToAnalyse?: number): Promise<void> {
    const userLogins = await this.fetchLoginData(daysToAnalyse);
    for (const user of users.values()) {
      if (userLogins.has(user.userId)) {
        user.logins = userLogins.get(user.userId);
      } else {
        user.logins = [];
      }
    }
  }

  private async resolvePermissions(users: Map<string, User>, withMetadata: boolean): Promise<void> {
    await this.resolvePermSetAssignments(users);
    if (withMetadata) {
      await this.resolveProfiles(users);
      await this.resolvePermissionSets(users);
    }
  }

  private async fetchLoginData(daysToAnalyse?: number): Promise<Map<string, UserLogins[]>> {
    const loginHistory = await this.connection.query<SfUserLoginsAggregate>(buildLoginHistoryQuery(daysToAnalyse));
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

  private async resolvePermSetAssignments(users: Map<string, User>): Promise<void> {
    const userIds = Array.from(users.values()).map((usr) => usr.userId);
    const assignments = await this.fetchAssignments(userIds);
    for (const user of users.values()) {
      user.assignments = assignments.get(user.userId) ?? [];
    }
  }

  private async resolveProfiles(users: Map<string, User>): Promise<void> {
    const profiles = await this.mdapiRepo.resolve('Profile', uniqueProfileNames(users.values()));
    for (const user of users.values()) {
      user.profileMetadata = profiles[user.profileName];
    }
  }

  private async resolvePermissionSets(users: Map<string, User>): Promise<void> {
    const permSetNames = uniquePermissionSetNames(users.values());
    const permsets = await this.mdapiRepo.resolve('PermissionSet', permSetNames);
    for (const user of users.values()) {
      for (const ass of user.assignments!) {
        ass.metadata = permsets[ass.permissionSetIdentifier];
      }
    }
  }

  private async fetchAssignments(userIds: string[]): Promise<Map<string, PermissionSetAssignment[]>> {
    const assignments = new Map<string, PermissionSetAssignment[]>();
    const rawAssignment = await this.connection.query<SfPermissionSetAssignment>(buildPermsetAssignmentsQuery(userIds));
    for (const assignment of rawAssignment.records) {
      if (isNullish(assignments.get(assignment.AssigneeId))) {
        assignments.set(assignment.AssigneeId, []);
      }
      assignments.get(assignment.AssigneeId)!.push({
        permissionSetIdentifier: assignment.PermissionSet.Name,
        permissionSetSource: assignment.PermissionSetGroupId ? 'group' : 'direct',
        ...(assignment.PermissionSetGroup?.DeveloperName && {
          groupName: assignment.PermissionSetGroup?.DeveloperName,
        }),
      });
    }
    return assignments;
  }
}

function uniquePermissionSetNames(users: Iterable<User>): string[] {
  const permSetNames = new Set<string>();
  for (const usr of users) {
    if (usr.assignments) {
      for (const ass of usr.assignments) {
        permSetNames.add(ass.permissionSetIdentifier);
      }
    }
  }
  return Array.from(permSetNames);
}

function uniqueProfileNames(users: Iterable<User>): string[] {
  const uniqueProfiles = new Set<string>();
  for (const usr of users) {
    uniqueProfiles.add(usr.profileName);
  }
  return Array.from(uniqueProfiles);
}

type SfUser = Record & {
  Username: string;
  LastLoginDate?: string;
  CreatedDate: string;
  Profile: SfProfile;
  IsActive: boolean;
};

type SfProfile = Record & {
  Id: string;
  Name: string;
  UserType: string;
};

type SfUserLoginsAggregate = Record & {
  LoginType: string;
  Application: string;
  UserId: string;
  LoginCount: number;
  LastLogin: string;
};

type SfPermissionSetAssignment = Record & {
  AssigneeId: string;
  PermissionSet: Pick<SfPermissionSet, 'Name'>;
  PermissionSetGroupId?: string;
  PermissionSetGroup?: SfPermissionSetGroup;
};

type SfPermissionSet = Record & {
  Id: string;
  IsOwnedByProfile: boolean;
  IsCustom: boolean;
  Name: string;
  Label: string;
  Profile: SfProfile;
  NamespacePrefix?: string;
};

type SfPermissionSetGroup = Record & {
  DeveloperName: string;
};
