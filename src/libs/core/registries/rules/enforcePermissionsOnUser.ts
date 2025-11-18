import { buildPermsetAssignmentsQuery } from '../../constants.js';
import MDAPI from '../../mdapi/mdapiRetriever.js';
import { PermissionSetAssignment } from '../../policies/salesforceStandardTypes.js';
import { isNullish } from '../../utils.js';
import { PartialProfileLike, scanProfileLike, ScanResult } from '../helpers/permissionsScanning.js';
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
    const assignments = await fetchAssignments(context, Object.values(users));
    const mdapiRepo = MDAPI.create(context.targetOrgConnection);
    const permsets = await mdapiRepo.resolve('PermissionSet', uniquePermSetNames(assignments));
    const profiles = await mdapiRepo.resolve('Profile', uniqueProfileNames(Object.values(users)));
    for (const user of Object.values(users)) {
      const resolvedPermsetAssignments = assignments[user.userId]
        ? assignments[user.userId].map((ass) => ({
            ...ass,
            metadata: permsets[ass.permissionSetIdentifier],
          }))
        : [];
      const permsetResult = this.scanAssignedPermissionSets(user, resolvedPermsetAssignments);
      result.violations.push(...permsetResult.violations);
      result.warnings.push(...permsetResult.warnings);
      const profileResult = scanProfileLike(
        { preset: user.role, metadata: profiles[user.assignedProfile], name: user.assignedProfile },
        this.auditContext,
        [user.username]
      );
      result.violations.push(...profileResult.violations);
      result.warnings.push(...profileResult.warnings);
    }
    return result;
  }

  private scanAssignedPermissionSets(user: ResolvedUser, actualAssignments: ResolvedAssignment[]): ScanResult {
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

async function fetchAssignments(context: AuditContext, users: ResolvedUser[]): Promise<UserPermSetAssignments> {
  const permSetAssignments: Awaited<ReturnType<typeof fetchAssignments>> = {};
  const assignments = await context.targetOrgConnection.query<PermissionSetAssignment>(
    buildPermsetAssignmentsQuery(users.map((u) => u.userId))
  );
  for (const assignment of assignments.records) {
    if (isNullish(permSetAssignments[assignment.AssigneeId])) {
      permSetAssignments[assignment.AssigneeId] = [];
    }
    permSetAssignments[assignment.AssigneeId].push({
      permissionSetIdentifier: assignment.PermissionSet.Name,
      permissionSetSource: assignment.PermissionSetGroupId ? 'group' : 'direct',
      groupName: assignment.PermissionSetGroup?.DeveloperName,
    });
  }
  return permSetAssignments;
}

function uniquePermSetNames(assignments: UserPermSetAssignments): string[] {
  const uniquePermSets = new Set<string>();
  for (const assList of Object.values(assignments)) {
    for (const ass of assList) {
      uniquePermSets.add(ass.permissionSetIdentifier);
    }
  }
  return Array.from(uniquePermSets);
}

function uniqueProfileNames(users: ResolvedUser[]): string[] {
  const uniqueProfiles = new Set<string>();
  for (const usr of users) {
    uniqueProfiles.add(usr.assignedProfile);
  }
  return Array.from(uniqueProfiles);
}
