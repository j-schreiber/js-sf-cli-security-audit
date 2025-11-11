import { Messages } from '@salesforce/core';
import { EntityResolveError } from '../result-types.js';
import { AuditRunConfig, UsersPolicyFileContent } from '../file-mgmt/schema.js';
import { AuditContext } from '../registries/types.js';
import { ACTIVE_USERS_DETAILS_QUERY, buildLoginHistoryQuery } from '../constants.js';
import { ResolvedUser, UsersRegistry } from '../registries/users.js';
import { ProfilesRiskPreset } from '../policy-types.js';
import Policy, { getTotal, ResolveEntityResult } from './policy.js';
import { User, UserLoginsAggregate } from './salesforceStandardTypes.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policies.general');

export default class UserPolicy extends Policy<ResolvedUser> {
  private totalEntities: number;
  public constructor(
    public config: UsersPolicyFileContent,
    public auditConfig: AuditRunConfig,
    registry = UsersRegistry
  ) {
    super(config, auditConfig, registry);
    this.totalEntities = this.config.users ? Object.keys(this.config.users).length : 0;
  }

  protected async resolveEntities(context: AuditContext): Promise<ResolveEntityResult<ResolvedUser>> {
    this.emit('entityresolve', {
      total: this.totalEntities,
      resolved: 0,
    });
    const usersById: Record<string, ResolvedUser> = {};
    const ignoredEntities: Record<string, EntityResolveError> = {};
    const configuredUsers = this.config.users ?? {};
    const classifiedUsers = [];
    const userIds: string[] = [];
    Object.entries(configuredUsers).forEach(([userName, userDef]) => {
      if (userDef.role === ProfilesRiskPreset.UNKNOWN) {
        ignoredEntities[userName] = {
          name: userName,
          message: messages.getMessage('user-with-role-unknown'),
        };
      } else {
        classifiedUsers.push(userName);
      }
    });
    // fetch all users from org and merge with configured users
    const allUsersOnOrg = await context.targetOrgConnection.query<User>(ACTIVE_USERS_DETAILS_QUERY);
    allUsersOnOrg.records.forEach((user) => {
      if (ignoredEntities[user.Username] === undefined) {
        usersById[user.Id!] = {
          userId: user.Id!,
          username: user.Username,
          lastLogin: user.LastLoginDate ? Date.parse(user.LastLoginDate) : undefined,
          createdDate: Date.parse(user.CreatedDate),
          assignedProfile: user.Profile.Name,
          assignedPermissionSets: [],
          logins: [],
          role: configuredUsers[user.Username]?.role ?? this.config.options.defaultRoleForMissingUsers,
        };
        userIds.push(user.Id!);
      }
    });
    this.totalEntities = allUsersOnOrg.totalSize;
    this.emit('entityresolve', {
      total: this.totalEntities,
      resolved: 0,
    });
    const userLogins = await resolveLogins(context, this.config.options.analyseLastNDaysOfLoginHistory);
    Object.entries(userLogins).forEach(([userId, user]) => {
      if (usersById[userId] !== undefined) {
        usersById[userId].logins = user.logins;
      }
    });
    // resolve perm set assignments per user
    // const assignments = await context.targetOrgConnection.query<PermissionSetAssignment>(
    //   buildPermsetAssignmentsQuery(userIds)
    // );
    // assignments.records.forEach(assignment => {

    // })
    const result = { resolvedEntities: organizeByUsername(usersById), ignoredEntities: Object.values(ignoredEntities) };
    this.emit('entityresolve', {
      total: this.totalEntities,
      resolved: getTotal(result),
    });
    return result;
  }
}

async function resolveLogins(context: AuditContext, daysToAnalyse?: number): Promise<PartialUsersRecord> {
  const loginHistory = await context.targetOrgConnection.query<UserLoginsAggregate>(
    buildLoginHistoryQuery(daysToAnalyse)
  );
  const partialUsers: Awaited<ReturnType<typeof resolveLogins>> = {};
  loginHistory.records.forEach((loginHistoryRow) => {
    if (!partialUsers[loginHistoryRow.UserId]) {
      partialUsers[loginHistoryRow.UserId] = { logins: [] };
    }
    partialUsers[loginHistoryRow.UserId].logins.push({
      loginType: loginHistoryRow.LoginType,
      loginCount: loginHistoryRow.LoginCount,
      application: loginHistoryRow.Application,
      lastLogin: Date.parse(loginHistoryRow.LastLogin),
    });
  });
  return partialUsers;
}

type PartialUsersRecord = Record<string, Pick<ResolvedUser, 'logins'>>;

function organizeByUsername(partial: Record<string, ResolvedUser>): Record<string, ResolvedUser> {
  const full: Record<string, ResolvedUser> = {};
  Object.values(partial).forEach((resolved) => {
    full[resolved.username] = resolved;
  });
  return full;
}
