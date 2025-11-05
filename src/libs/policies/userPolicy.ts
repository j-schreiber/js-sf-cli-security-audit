import { Messages } from '@salesforce/core';
import { EntityResolveError } from '../core/result-types.js';
import { AuditRunConfig, UsersPolicyFileContent } from '../core/file-mgmt/schema.js';
import { AuditContext, RuleRegistries } from '../core/registries/types.js';
import { ACTIVE_USERS_DETAILS_QUERY } from '../core/constants.js';
import { ResolvedUser } from '../core/registries/users.js';
import { ProfilesRiskPreset } from '../core/policy-types.js';
import Policy, { getTotal, ResolveEntityResult } from './policy.js';
import { User } from './salesforceStandardTypes.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policies.general');

export default class UserPolicy extends Policy<ResolvedUser> {
  private totalEntities: number;
  public constructor(
    public config: UsersPolicyFileContent,
    public auditConfig: AuditRunConfig,
    registry = RuleRegistries.Users
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
    const users = await context.targetOrgConnection.query<User>(ACTIVE_USERS_DETAILS_QUERY);
    users.records.forEach((user) => {
      if (ignoredEntities[user.Username] === undefined) {
        usersById[user.Id!] = {
          userId: user.Id!,
          username: user.Username,
          assignedProfile: user.Profile.Name,
          assignedPermissionSets: [],
          role: configuredUsers[user.Username]?.role ?? this.config.options.defaultRoleForMissingUsers,
        };
        userIds.push(user.Id!);
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

function organizeByUsername(partial: Record<string, ResolvedUser>): Record<string, ResolvedUser> {
  const full: Record<string, ResolvedUser> = {};
  Object.values(partial).forEach((resolved) => {
    full[resolved.username] = resolved;
  });
  return full;
}
