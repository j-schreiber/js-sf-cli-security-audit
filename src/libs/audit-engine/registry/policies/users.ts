import { Messages } from '@salesforce/core';
import RuleRegistry from '../ruleRegistry.js';
import { ResolveUsersOptions, User, Users } from '../../../../salesforce/index.js';
import Policy, { getTotal, ResolveEntityResult } from '../policy.js';
import { AuditContext } from '../context.types.js';
import { EntityResolveError } from '../result.types.js';
import { UserClassifications, UserPolicyConfig, UserPrivilegeLevel } from '../shape/schema.js';
import { AuditRunConfig } from '../shape/auditConfigShape.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policies.general');

export type ResolvedUser = User & {
  role: UserPrivilegeLevel;
};

export default class UsersPolicy extends Policy<ResolvedUser> {
  private totalEntities: number;
  private readonly classifications: UserClassifications;
  private readonly resolveOptions: Partial<ResolveUsersOptions>;

  public constructor(public config: UserPolicyConfig, public auditConfig: AuditRunConfig, registry: RuleRegistry) {
    super('users', config, auditConfig, registry);
    this.classifications = this.auditConfig.classifications.users?.users ?? {};
    this.totalEntities = Object.keys(this.classifications).length;
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
        role: this.classifications[user.username]?.role ?? this.config.options.defaultRoleForMissingUsers,
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

function buildResolveOptions(policyConfig: UserPolicyConfig): Partial<ResolveUsersOptions> {
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
  if (policyConfig.rules['NoStandardProfilesOnActiveUsers']) {
    opts.withPermissions = true;
    opts.withPermissionsMetadata = true;
  }
  return opts;
}
