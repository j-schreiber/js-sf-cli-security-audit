import { ResolvedUser } from '../../policies/userPolicy.js';
import { scanProfileLike, ScanResult } from '../helpers/permissionsScanning.js';
import { PartialPolicyRuleResult, RuleAuditContext } from '../types.js';
import PolicyRule, { RuleOptions } from './policyRule.js';

export default class EnforcePermissionsOnUser extends PolicyRule<ResolvedUser> {
  public constructor(opts: RuleOptions) {
    super(opts);
  }

  public run(context: RuleAuditContext<ResolvedUser>): Promise<PartialPolicyRuleResult> {
    const result = this.initResult();
    const users = context.resolvedEntities;
    for (const user of Object.values(users)) {
      const { violations, warnings } = this.scanAssignedPermissionSets(user, user.assignments);
      result.violations.push(...violations);
      result.warnings.push(...warnings);
      if (user.profileMetadata) {
        const profileResult = scanProfileLike(
          { role: user.role, metadata: user.profileMetadata, name: user.profileName },
          this.auditContext,
          [user.username]
        );
        result.violations.push(...profileResult.violations);
        result.warnings.push(...profileResult.warnings);
      }
    }
    return Promise.resolve(result);
  }

  private scanAssignedPermissionSets(user: ResolvedUser, assignments: ResolvedUser['assignments']): ScanResult {
    const result: ScanResult = { violations: [], warnings: [] };
    if (!assignments) {
      return result;
    }
    for (const assignedPermSet of assignments) {
      if (!assignedPermSet.metadata) {
        continue;
      }
      const permsetScan = scanProfileLike(
        { role: user.role, metadata: assignedPermSet.metadata, name: assignedPermSet.permissionSetIdentifier },
        this.auditContext,
        [user.username]
      );
      result.violations.push(...permsetScan.violations);
      result.warnings.push(...permsetScan.warnings);
    }
    return result;
  }
}
