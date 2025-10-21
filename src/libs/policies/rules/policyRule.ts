import { Messages } from '@salesforce/core';
import { PolicyRuleViolation, PolicyRuleViolationMute, RuleComponentMessage } from '../../audit/types.js';
import { PartialPolicyRuleResult, RowLevelPolicyRule, RuleAuditContext } from '../interfaces/policyRuleInterfaces.js';
import {
  AuditRunConfig,
  NamedPermissionsClassification,
  PermissionsClassification,
} from '../../config/audit-run/schema.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);

export type RuleOptions = {
  auditContext: AuditRunConfig;
  ruleDisplayName: string;
  ruleConfig?: unknown;
};

export default abstract class PolicyRule<EntityType> implements RowLevelPolicyRule<EntityType> {
  public auditContext: AuditRunConfig;
  public ruleDisplayName: string;

  public constructor(opts: RuleOptions) {
    this.auditContext = opts.auditContext;
    this.ruleDisplayName = opts.ruleDisplayName;
  }

  protected initResult(): PartialPolicyRuleResult {
    return {
      ruleName: this.ruleDisplayName,
      violations: new Array<PolicyRuleViolation>(),
      mutedViolations: new Array<PolicyRuleViolationMute>(),
      warnings: new Array<RuleComponentMessage>(),
      errors: new Array<RuleComponentMessage>(),
    };
  }

  protected resolveUserPermission(permName: string): NamedPermissionsClassification | undefined {
    return nameClassification(
      permName,
      this.auditContext.classifications.userPermissions?.content.permissions[permName]
    );
  }

  protected resolveCustomPermission(permName: string): NamedPermissionsClassification | undefined {
    return nameClassification(
      permName,
      this.auditContext.classifications.customPermissions?.content.permissions[permName]
    );
  }

  public abstract run(context: RuleAuditContext<EntityType>): Promise<PartialPolicyRuleResult>;
}

function nameClassification(
  permName: string,
  perm?: PermissionsClassification
): NamedPermissionsClassification | undefined {
  return perm ? { name: permName, ...perm } : undefined;
}
