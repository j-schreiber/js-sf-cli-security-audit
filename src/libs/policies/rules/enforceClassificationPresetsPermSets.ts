import { Connection, Messages } from '@salesforce/core';
import { PermissionSet } from '@jsforce/jsforce-node/lib/api/metadata.js';
import { PolicyRuleExecutionResult, PolicyRuleViolation, RuleComponentMessage } from '../../audit/types.js';
import { RowLevelPolicyRule, AuditContext } from '../interfaces/policyRuleInterfaces.js';
import { PermissionSetLikeMap } from '../schema.js';
import { permissionAllowedInPreset, PermissionRiskLevelPresets, PolicyRiskLevel } from '../types.js';
import AuditRunConfig from '../interfaces/auditRunConfig.js';
import MdapiRetriever from '../../mdapiRetriever.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.enforceClassificationPresets');

type ResolvedPermissionSet = {
  name: string;
  preset: string;
  metadata: PermissionSet;
};

export default class EnforceClassificationPresetsPermSets implements RowLevelPolicyRule {
  private definitivePermSets: PermissionSetLikeMap;

  public constructor(private auditContext: AuditRunConfig) {
    if (auditContext.policies.PermissionSets) {
      this.definitivePermSets = auditContext.policies.PermissionSets.content.permissionSets;
    } else {
      this.definitivePermSets = {};
    }
  }

  public async run(context: AuditContext): Promise<PolicyRuleExecutionResult> {
    const result = {
      ruleName: 'EnforceClassificationPresets',
      isCompliant: true,
      violations: new Array<PolicyRuleViolation>(),
      mutedViolations: [],
      warnings: new Array<RuleComponentMessage>(),
      errors: [],
    };
    const resolvedPermsets = await this.resolvePermissionSets(context.targetOrgConnection);
    Object.values(resolvedPermsets).forEach((permset) => {
      const userPerms = permset.metadata.userPermissions ?? [];
      userPerms.forEach((userPerm) => {
        const identifier = [permset.name, userPerm.name];
        const classifiedUserPerm = this.auditContext.resolveUserPermission(userPerm.name);
        if (classifiedUserPerm) {
          if (classifiedUserPerm.classification === PolicyRiskLevel.BLOCKED) {
            result.violations.push({
              identifier,
              message: messages.getMessage('violations.permission-is-blocked'),
            });
          } else if (!permissionAllowedInPreset(classifiedUserPerm.classification, permset.preset)) {
            result.violations.push({
              identifier,
              message: messages.getMessage('violations.classification-preset-mismatch', [
                classifiedUserPerm.classification,
                permset.preset,
              ]),
            });
          } else if (classifiedUserPerm.classification === PolicyRiskLevel.UNKNOWN) {
            result.warnings.push({
              identifier,
              message: messages.getMessage('warnings.permission-unknown'),
            });
          }
        } else {
          result.warnings.push({
            identifier,
            message: messages.getMessage('warnings.permission-not-classified-in-permission-set'),
          });
        }
      });
    });
    return result;
  }

  private async resolvePermissionSets(con: Connection): Promise<Record<string, ResolvedPermissionSet>> {
    const result: Record<string, ResolvedPermissionSet> = {};
    const retriever = new MdapiRetriever(con);
    const resolvedPermsets = await retriever.retrievePermissionsets(this.filterCategorizedPermsets());
    Object.entries(resolvedPermsets).forEach(([permsetName, resolvedPermset]) => {
      result[permsetName] = {
        metadata: resolvedPermset,
        preset: this.definitivePermSets[permsetName].preset,
        name: permsetName,
      };
    });
    return result;
  }

  private filterCategorizedPermsets(): string[] {
    const filteredNames: string[] = [];
    Object.entries(this.definitivePermSets).forEach(([key, val]) => {
      if (val.preset !== PermissionRiskLevelPresets.UNKNOWN) {
        filteredNames.push(key);
      }
    });
    return filteredNames;
  }
}
