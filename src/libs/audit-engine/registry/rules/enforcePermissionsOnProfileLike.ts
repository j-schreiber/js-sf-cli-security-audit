import { isNullish } from '../../../../utils.js';
import { PartialPolicyRuleResult, RuleAuditContext } from '../context.types.js';
import { ResolvedProfileLike, scanPermissions } from '../helpers/permissionsScanning.js';
import PolicyRule, { RuleOptions } from './policyRule.js';

export default class EnforcePermissionsOnProfileLike extends PolicyRule<ResolvedProfileLike> {
  public constructor(opts: RuleOptions) {
    super(opts);
  }

  public run(context: RuleAuditContext<ResolvedProfileLike>): Promise<PartialPolicyRuleResult> {
    const result = this.initResult();
    const resolvedProfiles = context.resolvedEntities;
    for (const profile of Object.values(resolvedProfiles)) {
      if (!isNullish(profile.metadata.userPermissions)) {
        const userPermsScan = scanPermissions(profile, 'userPermissions', this.auditConfig);
        result.violations.push(...userPermsScan.violations);
        result.warnings.push(...userPermsScan.warnings);
      }
      if (!isNullish(profile.metadata.customPermissions)) {
        const customPermsScan = scanPermissions(profile, 'customPermissions', this.auditConfig);
        result.violations.push(...customPermsScan.violations);
        result.warnings.push(...customPermsScan.warnings);
      }
    }
    return Promise.resolve(result);
  }
}
