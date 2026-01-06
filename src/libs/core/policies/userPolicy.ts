import { Messages } from '@salesforce/core';
import { EntityResolveError } from '../result-types.js';
import { AuditRunConfig, UsersClassificationContent, UsersPolicyFileContent } from '../file-mgmt/schema.js';
import { AuditContext } from '../registries/types.js';
import { ResolvedUser, UsersRegistry } from '../registries/users.js';
import { UserPrivilegeLevel } from '../policy-types.js';
import UsersRepository from '../mdapi/usersRepository.js';
import Policy, { getTotal, ResolveEntityResult } from './policy.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policies.general');

export default class UserPolicy extends Policy<ResolvedUser> {
  private totalEntities: number;
  private readonly classifications: UsersClassificationContent;

  public constructor(
    public config: UsersPolicyFileContent,
    public auditConfig: AuditRunConfig,
    registry = UsersRegistry
  ) {
    super(config, auditConfig, registry);
    this.classifications = this.auditConfig.classifications.users?.content ?? { users: {} };
    this.totalEntities = Object.keys(this.classifications.users).length;
  }

  protected async resolveEntities(context: AuditContext): Promise<ResolveEntityResult<ResolvedUser>> {
    this.emit('entityresolve', {
      total: this.totalEntities,
      resolved: 0,
    });
    const usersRepo = new UsersRepository(context.targetOrgConnection);
    const resolvedEntities: Record<string, ResolvedUser> = {};
    const ignoredEntities: Record<string, EntityResolveError> = {};
    for (const [userName, userDef] of Object.entries(this.classifications.users)) {
      if (userDef.role === UserPrivilegeLevel.UNKNOWN) {
        ignoredEntities[userName] = {
          name: userName,
          message: messages.getMessage('user-with-role-unknown'),
        };
      }
    }
    // fetch all users from org and merge with configured users
    const allUsersOnOrg = await usersRepo.resolveAllUsers({
      withLoginHistory: true,
      loginHistoryDaysToAnalyse: this.config.options.analyseLastNDaysOfLoginHistory,
    });
    this.totalEntities = allUsersOnOrg.size;
    this.emit('entityresolve', {
      total: this.totalEntities,
      resolved: 0,
    });
    for (const user of allUsersOnOrg.values()) {
      if (ignoredEntities[user.username] === undefined) {
        resolvedEntities[user.username] = {
          ...user,
          role: this.classifications.users[user.username]?.role ?? this.config.options.defaultRoleForMissingUsers,
        };
      }
    }
    const result = { resolvedEntities, ignoredEntities: Object.values(ignoredEntities) };
    this.emit('entityresolve', {
      total: this.totalEntities,
      resolved: getTotal(result),
    });
    return result;
  }
}
