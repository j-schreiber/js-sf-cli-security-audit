import { Messages } from '@salesforce/core';
import { AuditRunConfig, UsersClassificationContent, UsersPolicyFileContent } from '../file-mgmt/schema.js';
import { AuditContext } from '../registries/types.js';
import { ResolveUsersOptions, User, Users } from '../salesforce-apis/index.js';
import { UsersRegistry } from '../registries/users.js';
import { EntityResolveError } from '../result-types.js';
import { UserPrivilegeLevel } from '../policy-types.js';
import Policy, { getTotal, ResolveEntityResult } from './policy.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policies.general');

export type ResolvedUser = User & {
  role: UserPrivilegeLevel;
};

export default class UserPolicy extends Policy<ResolvedUser> {
  private totalEntities: number;
  private readonly classifications: UsersClassificationContent;
  private readonly resolveOptions: Partial<ResolveUsersOptions>;

  public constructor(
    public config: UsersPolicyFileContent,
    public auditConfig: AuditRunConfig,
    registry = UsersRegistry
  ) {
    super(config, auditConfig, registry);
    this.classifications = this.auditConfig.classifications.users?.content ?? { users: {} };
    this.totalEntities = Object.keys(this.classifications.users).length;
    this.resolveOptions = buildResolveOptions(this.config);
  }

  protected async resolveEntities(context: AuditContext): Promise<ResolveEntityResult<ResolvedUser>> {
    this.emit('entityresolve', {
      total: this.totalEntities,
      resolved: 0,
    });
    const usersRepo = new Users(context.targetOrgConnection);
    const allUsersOnOrg = await usersRepo.resolve(this.resolveOptions);
    this.totalEntities = allUsersOnOrg.size;
    this.emit('entityresolve', {
      total: this.totalEntities,
      resolved: 0,
    });
    const result = this.finaliseResolvedUsers(allUsersOnOrg);
    this.emit('entityresolve', {
      total: this.totalEntities,
      resolved: getTotal(result),
    });
    return result;
  }

  private finaliseResolvedUsers(users: Map<string, User>): ResolveEntityResult<ResolvedUser> {
    const resolvedEntities: Record<string, ResolvedUser> = {};
    const ignoredEntities: Record<string, EntityResolveError> = {};
    for (const user of users.values()) {
      const finalUser: ResolvedUser = {
        ...user,
        role: this.classifications.users[user.username]?.role ?? this.config.options.defaultRoleForMissingUsers,
      };
      if (finalUser.role === UserPrivilegeLevel.UNKNOWN) {
        ignoredEntities[user.username] = {
          name: user.username,
          message: messages.getMessage('user-with-role-unknown'),
        };
      } else {
        resolvedEntities[user.username] = finalUser;
      }
    }
    return { resolvedEntities, ignoredEntities: Object.values(ignoredEntities) };
  }
}

function buildResolveOptions(policyConfig: UsersPolicyFileContent): Partial<ResolveUsersOptions> {
  const opts: Partial<ResolveUsersOptions> = {};
  if (policyConfig.rules['NoOtherApexApiLogins'] || policyConfig.rules['NoInactiveUsers']) {
    opts.withLoginHistory = true;
    opts.loginHistoryDaysToAnalyse = policyConfig.options.analyseLastNDaysOfLoginHistory;
  }
  if (policyConfig.rules['EnforcePermissionPresets']) {
    opts.withPermissions = true;
  }
  if (policyConfig.rules['EnforcePermissionClassifications']) {
    opts.withPermissions = true;
    opts.withPermissionsMetadata = true;
  }
  return opts;
}
