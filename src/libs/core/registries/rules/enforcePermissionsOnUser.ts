import UsersRepository, { PermissionSetAssignment } from '../../mdapi/usersRepository.js';
import { scanProfileLike, ScanResult } from '../helpers/permissionsScanning.js';
import { PartialPolicyRuleResult, RuleAuditContext } from '../types.js';
import { ResolvedUser } from '../users.js';
import PolicyRule, { RuleOptions } from './policyRule.js';

export default class EnforcePermissionsOnUser extends PolicyRule<ResolvedUser> {
  public constructor(opts: RuleOptions) {
    super(opts);
  }

  public async run(context: RuleAuditContext<ResolvedUser>): Promise<PartialPolicyRuleResult> {
    const result = this.initResult();
    const users = context.resolvedEntities;
    const userRepo = new UsersRepository(context.targetOrgConnection);
    const userPerms = await userRepo.resolveUserPermissions(Object.values(users));
    for (const user of Object.values(users)) {
      const resolvedPerms = userPerms.get(user.userId);
      if (!resolvedPerms) {
        continue;
      }
      const permsetResult = this.scanAssignedPermissionSets(user, resolvedPerms.assignedPermissionsets);
      result.violations.push(...permsetResult.violations);
      result.warnings.push(...permsetResult.warnings);
      if (resolvedPerms.profileMetadata) {
        const profileResult = scanProfileLike(
          { preset: user.role, metadata: resolvedPerms.profileMetadata, name: user.profileName },
          this.auditContext,
          [user.username]
        );
        result.violations.push(...profileResult.violations);
        result.warnings.push(...profileResult.warnings);
      }
    }
    return result;
  }

  private scanAssignedPermissionSets(user: ResolvedUser, actualAssignments: PermissionSetAssignment[]): ScanResult {
    const result: ScanResult = { violations: [], warnings: [] };
    for (const assignedPermSet of actualAssignments) {
      if (!assignedPermSet.metadata) {
        continue;
      }
      const permsetScan = scanProfileLike(
        { preset: user.role, metadata: assignedPermSet.metadata, name: assignedPermSet.permissionSetIdentifier },
        this.auditContext,
        [user.username]
      );
      result.violations.push(...permsetScan.violations);
      result.warnings.push(...permsetScan.warnings);
    }
    return result;
  }
}
