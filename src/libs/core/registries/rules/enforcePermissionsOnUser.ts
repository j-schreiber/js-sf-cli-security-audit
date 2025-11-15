import { buildPermsetAssignmentsQuery } from '../../constants.js';
import MDAPI from '../../mdapi/mdapiRetriever.js';
import { PermissionSetAssignment } from '../../policies/salesforceStandardTypes.js';
import { isNullish } from '../../utils.js';
import { PartialProfileLike, scanPermissions, ScanResult } from '../helpers/permissionsScanning.js';
import { AuditContext, PartialPolicyRuleResult, RuleAuditContext } from '../types.js';
import { ResolvedUser, UserPermissionSetAssignment } from '../users.js';
import PolicyRule, { RuleOptions } from './policyRule.js';

type UserPermSetAssignments = Record<string, UserPermissionSetAssignment[]>;

type ResolvedAssignment = UserPermissionSetAssignment & {
  metadata?: PartialProfileLike;
};

export default class EnforcePermissionsOnUser extends PolicyRule<ResolvedUser> {
  public constructor(opts: RuleOptions) {
    super(opts);
  }

  public async run(context: RuleAuditContext<ResolvedUser>): Promise<PartialPolicyRuleResult> {
    const result = this.initResult();
    const users = context.resolvedEntities;
    const assignments = await resolveAssignments(context, Object.values(users));
    const usedPermSetNames = getPermissionSetsInUse(assignments);
    if (usedPermSetNames.length === 0) {
      return result;
    }
    const permsetRepo = MDAPI.create(context.targetOrgConnection);
    const permsets = await permsetRepo.resolve('PermissionSet', usedPermSetNames);
    for (const user of Object.values(users)) {
      const resolvedPermsetAssignments = assignments[user.userId]
        ? assignments[user.userId].map((ass) => ({
            ...ass,
            metadata: permsets[ass.permissionSetIdentifier],
          }))
        : [];
      const userResult = this.scanAssignedPermissionSets(user, resolvedPermsetAssignments);
      result.violations.push(...userResult.violations);
      result.warnings.push(...userResult.warnings);
    }
    return result;
  }

  private scanAssignedPermissionSets(user: ResolvedUser, actualAssignments: ResolvedAssignment[]): ScanResult {
    const result: ScanResult = { violations: [], warnings: [] };
    for (const assignedPermSet of actualAssignments) {
      if (!assignedPermSet.metadata) {
        continue;
      }
      const permsetScan = scanPermissions(
        { preset: user.role, metadata: assignedPermSet.metadata, name: assignedPermSet.permissionSetIdentifier },
        'userPermissions',
        this.auditContext,
        [user.username]
      );
      result.violations.push(...permsetScan.violations);
      result.warnings.push(...permsetScan.warnings);
    }
    return result;
  }
}

async function resolveAssignments(context: AuditContext, users: ResolvedUser[]): Promise<UserPermSetAssignments> {
  const permSetAssignments: Awaited<ReturnType<typeof resolveAssignments>> = {};
  const assignments = await context.targetOrgConnection.query<PermissionSetAssignment>(
    buildPermsetAssignmentsQuery(users.map((u) => u.userId))
  );
  for (const assignment of assignments.records) {
    if (isNullish(permSetAssignments[assignment.AssigneeId])) {
      permSetAssignments[assignment.AssigneeId] = [];
    }
    permSetAssignments[assignment.AssigneeId].push({
      permissionSetIdentifier: assignment.PermissionSet.Name,
      permissionSetSource: 'direct',
    });
  }
  return permSetAssignments;
}

function getPermissionSetsInUse(assignments: UserPermSetAssignments): string[] {
  const uniquePermSets = new Set<string>();
  for (const assList of Object.values(assignments)) {
    for (const ass of assList) {
      uniquePermSets.add(ass.permissionSetIdentifier);
    }
  }
  return Array.from(uniquePermSets);
}
