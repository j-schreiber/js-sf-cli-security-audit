import { Connection, Messages } from '@salesforce/core';
import { Record } from '@jsforce/jsforce-node';
import MDAPI from '../../mdapi/mdapi.js';
import { envVars } from '../../../ux/environment.js';
import { ResolveLifecycle } from '../../resolve-entity-lifecycle-bus.js';
import { chunkArray } from '../../utils.js';
import SfConnection from '../../connection.js';
import { ResolveUsersOptions, ResolveUsersOptionsSchema, User, UserLogins } from './user.types.js';
import { buildScopedLoginHistoryQuery, USERS_QUERY } from './queries.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'metadataretrieve');

export default class Users {
  private readonly mdapiRepo: MDAPI;
  private readonly usersMaxFetch;
  private readonly startingBatchSize;
  private readonly con: SfConnection;

  public constructor(coreConnection: Connection) {
    this.mdapiRepo = MDAPI.create(coreConnection);
    this.con = new SfConnection(coreConnection);
    this.usersMaxFetch = envVars.resolve('SAE_MAX_USERS_LIMIT') ?? 100_000;
    this.startingBatchSize = 256;
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
    const usersOnOrg = await this.fetchUsers(definitiveOpts);
    for (const user of usersOnOrg) {
      const usr: User = {
        userId: user.Id!,
        username: user.Username,
        lastLogin: user.LastLoginDate ? Date.parse(user.LastLoginDate) : undefined,
        isActive: Boolean(user.IsActive),
        createdDate: Date.parse(user.CreatedDate),
        profileName: user.Profile.Name,
      };
      if (definitiveOpts.withPermissions && user.PermissionSetAssignments) {
        usr.assignments = user.PermissionSetAssignments.records.map((assignment) => ({
          permissionSetIdentifier: assignment.PermissionSet.Name,
          permissionSetSource: assignment.PermissionSetGroupId ? 'group' : 'direct',
          ...(assignment.PermissionSetGroup?.DeveloperName && {
            groupName: assignment.PermissionSetGroup?.DeveloperName,
          }),
        }));
      } else if (definitiveOpts.withPermissions) {
        usr.assignments = [];
      }
      result.set(user.Username, usr);
    }
    if (definitiveOpts.withLoginHistory) {
      await this.resolveLogins(result, definitiveOpts.loginHistoryDaysToAnalyse);
    }
    if (definitiveOpts.withPermissionsMetadata) {
      await this.resolveProfiles(result);
      await this.resolvePermissionSets(result);
    }
    return result;
  }

  //        PRIVATE ZONE

  private async fetchUsers(opts: ResolveUsersOptions): Promise<SfUser[]> {
    const usersOnOrg = await this.con.query<SfUser>(USERS_QUERY, false, {
      autoFetch: true,
      maxFetch: this.usersMaxFetch,
    });
    if (usersOnOrg.totalSize > this.usersMaxFetch) {
      ResolveLifecycle.emitWarn(
        messages.getMessage('warning.TooManyActiveUsersIncreaseLimit', [usersOnOrg.totalSize, this.usersMaxFetch])
      );
    }
    return usersOnOrg.records.filter((user) => (opts.includeInactive ? true : user.IsActive));
  }

  private async resolveLogins(users: Map<string, User>, daysToAnalyse?: number): Promise<void> {
    const loginAggregates = await this.fetchLoginAggregates(
      Array.from(users.values()).map((user) => user.userId),
      daysToAnalyse
    );
    const userLogins = indexLoginData(loginAggregates.flat());
    for (const user of users.values()) {
      if (userLogins.has(user.userId)) {
        user.logins = userLogins.get(user.userId);
      } else {
        user.logins = [];
      }
    }
  }

  private async fetchLoginAggregates(userIds: string[], daysToAnalyse?: number): Promise<SfUserLoginsAggregate[]> {
    try {
      return await this.fetchLoginAggregateChunks(userIds, this.startingBatchSize, daysToAnalyse);
    } catch (error) {
      if (typeof error === 'object' && error != null && 'errorCode' in error) {
        // only split if it's aggregate queryMore() problem and we can still drill down
        if (error.errorCode === 'EXCEEDED_ID_LIMIT' && userIds.length >= 2) {
          // note for future me: This will fail, if a single user exists that has more than 2000 rows
          // in this aggregate query. This would require more than 2000 combinations of "LoginType"
          // and "Application" - time will tell if we need to add a dynamic LIMIT 2000 here with resolve warning.
          return await this.fetchLoginAggregateChunks(userIds, Math.floor(userIds.length / 2), daysToAnalyse);
        }
      }
      throw error;
    }
  }

  private async fetchLoginAggregateChunks(
    userIds: string[],
    chunkSize: number,
    daysToAnalyse?: number
  ): Promise<SfUserLoginsAggregate[]> {
    const initialIdChunks = chunkArray(userIds, chunkSize);
    const loginAggregateProms = initialIdChunks.map((idChunk) =>
      this.con.query<SfUserLoginsAggregate>(buildScopedLoginHistoryQuery(idChunk, daysToAnalyse))
    );
    const loginAggregates = await Promise.all(loginAggregateProms);
    return loginAggregates.map((queryResult) => queryResult.records).flat();
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
}

function indexLoginData(rawLogins: SfUserLoginsAggregate[]): Map<string, UserLogins[]> {
  const loginData = new Map<string, UserLogins[]>();
  for (const loginHistoryRow of rawLogins) {
    if (!loginData.has(loginHistoryRow.UserId)) {
      loginData.set(loginHistoryRow.UserId, []);
    }
    loginData.get(loginHistoryRow.UserId)!.push({
      loginType: loginHistoryRow.LoginType,
      loginCount: loginHistoryRow.LoginCount,
      application: loginHistoryRow.Application,
      lastLogin: Date.parse(loginHistoryRow.LastLogin),
      status: loginHistoryRow.Status,
    });
  }
  return loginData;
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
  PermissionSetAssignments?: {
    done: boolean;
    totalSize: number;
    records: SfPermissionSetAssignment[];
  } | null;
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
  Status: string;
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
