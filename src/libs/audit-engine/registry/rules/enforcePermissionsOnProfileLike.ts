import { PartialPolicyRuleResult, RuleAuditContext } from '../context.types.js';
import RoleManager from '../roles/roleManager.js';
import { ResolvedProfileLike } from '../roles/roleManager.types.js';
import PolicyRule, { RuleOptions } from './policyRule.js';

export default class EnforcePermissionsOnProfileLike extends PolicyRule<ResolvedProfileLike> {
  private readonly roleManager;

  public constructor(opts: RuleOptions) {
    super(opts);
    this.roleManager = new RoleManager({
      controls: opts.auditConfig.controls,
      shape: opts.auditConfig.shape,
    });
  }

  public run(context: RuleAuditContext<ResolvedProfileLike>): Promise<PartialPolicyRuleResult> {
    const result = this.initResult();
    const resolvedProfiles = context.resolvedEntities;
    for (const profile of Object.values(resolvedProfiles)) {
      const { errors, violations, warnings } = this.roleManager.scanPermissions(profile.role, profile);
      result.errors.push(...errors);
      result.warnings.push(...warnings);
      result.violations.push(...violations);
    }
    return Promise.resolve(result);
  }
}
