import { PartialPolicyRuleResult, RuleAuditContext } from '../context.types.js';
import { ProfileLike } from '../roles/roleManager.types.js';
import { ResolvedUser } from '../policies/users.js';
import PolicyRule, { RuleOptions } from './policyRule.js';

export default class EnforceObjectAccessOnUser extends PolicyRule<ResolvedUser> {
  public constructor(opts: RuleOptions) {
    super(opts);
  }

  public run(context: RuleAuditContext<ResolvedUser>): Promise<PartialPolicyRuleResult> {
    const result = this.initResult();
    const users = context.resolvedEntities;
    for (const user of Object.values(users)) {
      const profileLikes = buildProfileLikes(user);
      const { violations, warnings, errors } = this.opts.roles.scanObjectAccess(user.role, profileLikes, [
        user.username,
      ]);
      result.errors.push(...errors);
      result.warnings.push(...warnings);
      result.violations.push(...violations);
    }
    return Promise.resolve(result);
  }
}

function buildProfileLikes(user: ResolvedUser): ProfileLike[] {
  const profileLikes: ProfileLike[] = [];
  profileLikes.push({ metadata: user.profileMetadata, name: user.profileName, type: 'Profile' });
  for (const permSetAssignment of user.assignments ?? []) {
    profileLikes.push({
      metadata: permSetAssignment.metadata,
      name: permSetAssignment.permissionSetIdentifier,
      type: 'PermissionSet',
    });
  }
  return profileLikes;
}
