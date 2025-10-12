/* eslint-disable class-methods-use-this */
import { QueryResult } from '@jsforce/jsforce-node';
import { Connection, Messages } from '@salesforce/core';
import { Profile } from '@jsforce/jsforce-node/lib/api/metadata.js';
import { PolicyRuleExecutionResult, PolicyRuleViolation, RuleComponentMessage } from '../../audit/types.js';
import { RowLevelPolicyRule, AuditContext } from '../interfaces/policyRuleInterfaces.js';
import { PermissionSetLikeMap } from '../schema.js';
import { permissionAllowedInPreset, PermissionRiskLevelPresets, PolicyRiskLevel } from '../types.js';
import AuditRunConfig from '../interfaces/auditRunConfig.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.enforceClassificationPresets');

type ResolvedProfile = {
  name: string;
  preset: string;
  metadata: Profile;
};

type ProfileMetadata = {
  Name: string;
  Metadata: Profile;
};

export default class EnforceClassificationPresets implements RowLevelPolicyRule {
  private definitiveProfiles: PermissionSetLikeMap;

  public constructor(private auditContext: AuditRunConfig) {
    if (auditContext.policies.Profiles) {
      this.definitiveProfiles = auditContext.policies.Profiles.content.profiles;
    } else {
      this.definitiveProfiles = {};
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
    const resolvedProfiles = await this.resolveProfiles(context.targetOrgConnection);
    Object.values(resolvedProfiles).forEach((profile) => {
      profile.metadata.userPermissions.forEach((userPerm) => {
        const identifier = [profile.name, userPerm.name];
        const classifiedUserPerm = this.auditContext.resolveUserPermission(userPerm.name);
        if (classifiedUserPerm) {
          if (classifiedUserPerm.classification === PolicyRiskLevel.BLOCKED) {
            result.violations.push({
              identifier,
              message: messages.getMessage('violations.permission-is-blocked'),
            });
          } else if (!permissionAllowedInPreset(classifiedUserPerm.classification, profile.preset)) {
            result.violations.push({
              identifier,
              message: messages.getMessage('violations.classification-preset-mismatch', [
                classifiedUserPerm.classification,
                profile.preset,
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
            message: messages.getMessage('warnings.permission-not-classified-in-profile'),
          });
        }
      });
    });
    return result;
  }

  private async resolveProfiles(con: Connection): Promise<Record<string, ResolvedProfile>> {
    const profileQueryResults = Array<Promise<QueryResult<ProfileMetadata>>>();
    Object.entries(this.definitiveProfiles).forEach(([profileName, profileDef]) => {
      if (profileDef.preset !== PermissionRiskLevelPresets.UNKNOWN) {
        const qr = Promise.resolve(
          con.tooling.query<ProfileMetadata>(`SELECT Name,Metadata FROM Profile WHERE Name = '${profileName}'`)
        );
        profileQueryResults.push(qr);
      }
    });
    const queryResults = await Promise.all(profileQueryResults);
    const profileMetadata: Record<string, ResolvedProfile> = {};
    queryResults.forEach((qr) => {
      if (qr.records && qr.records.length > 0) {
        const record = qr.records[0];
        profileMetadata[record.Name] = {
          name: record.Name,
          preset: this.definitiveProfiles[record.Name].preset,
          metadata: record.Metadata,
        };
      }
    });
    return profileMetadata;
  }
}
