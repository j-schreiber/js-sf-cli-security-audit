import { Messages } from '@salesforce/core';
import { Profile } from '@jsforce/jsforce-node/lib/api/metadata.js';
import { PartialPolicyRuleResult, RuleAuditContext } from '../types.js';
import { isNullish } from '../../utils.js';
import { PermissionRiskLevel } from '../../classification-types.js';
import { permissionAllowedInPreset } from '../../policy-types.js';
import { PolicyRuleViolation, RuleComponentMessage } from '../../result-types.js';
import { AuditRunConfig, NamedPermissionsClassification, PermissionsClassification } from '../../file-mgmt/schema.js';
import { ClassificationNames } from '../../policyRegistry.js';
import PolicyRule, { RuleOptions } from './policyRule.js';

const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.enforceClassificationPresets');

export type ResolvedProfileLike = {
  name: string;
  preset: string;
  metadata: PartialProfileLike;
};

type PartialProfileLike = Pick<Profile, 'userPermissions' | 'customPermissions'>;
type PermissionsListKey = keyof PartialProfileLike;

type ScanResult = {
  violations: PolicyRuleViolation[];
  warnings: RuleComponentMessage[];
};

export default class EnforcePermissionsOnEntity extends PolicyRule<ResolvedProfileLike> {
  public constructor(opts: RuleOptions) {
    super(opts);
  }

  public run(context: RuleAuditContext<ResolvedProfileLike>): Promise<PartialPolicyRuleResult> {
    const result = this.initResult();
    const resolvedProfiles = context.resolvedEntities;
    for (const profile of Object.values(resolvedProfiles)) {
      if (!isNullish(profile.metadata.userPermissions)) {
        const userPermsScan = this.scanPermissions(profile, 'userPermissions');
        result.violations.push(...userPermsScan.violations);
        result.warnings.push(...userPermsScan.warnings);
      }
      if (!isNullish(profile.metadata.customPermissions)) {
        const customPermsScan = this.scanPermissions(profile, 'customPermissions');
        result.violations.push(...customPermsScan.violations);
        result.warnings.push(...customPermsScan.warnings);
      }
    }
    return Promise.resolve(result);
  }

  private scanPermissions(profile: ResolvedProfileLike, permissionListName: PermissionsListKey): ScanResult {
    const result: ScanResult = { warnings: [], violations: [] };
    for (const perm of profile.metadata[permissionListName]) {
      const identifier = [profile.name, perm.name];
      const permClassification = resolvePerm(perm.name, this.auditContext, permissionListName);
      if (permClassification) {
        if (permClassification.classification === PermissionRiskLevel.BLOCKED) {
          result.violations.push({
            identifier,
            message: messages.getMessage('violations.permission-is-blocked'),
          });
        } else if (!permissionAllowedInPreset(permClassification.classification, profile.preset)) {
          result.violations.push({
            identifier,
            message: messages.getMessage('violations.classification-preset-mismatch', [
              permClassification.classification,
              profile.preset,
            ]),
          });
        } else if (permClassification.classification === PermissionRiskLevel.UNKNOWN) {
          result.warnings.push({
            identifier,
            message: messages.getMessage('warnings.permission-unknown'),
          });
        }
      } else {
        result.warnings.push({
          identifier,
          message: messages.getMessage('warnings.permission-not-classified-in-profile'),
        });
      }
    }
    return result;
  }
}

function resolvePerm(
  permName: string,
  auditRun: AuditRunConfig,
  type: ClassificationNames
): NamedPermissionsClassification | undefined {
  return nameClassification(permName, auditRun.classifications[type]?.content.permissions[permName]);
}

function nameClassification(
  permName: string,
  perm?: PermissionsClassification
): NamedPermissionsClassification | undefined {
  return perm ? { name: permName, ...perm } : undefined;
}
