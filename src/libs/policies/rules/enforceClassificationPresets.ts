/* eslint-disable class-methods-use-this */
import { QueryResult } from '@jsforce/jsforce-node';
import { Profile } from '@jsforce/jsforce-node/lib/api/metadata.js';
import { PolicyRuleExecutionResult, PolicyRuleViolation } from '../../audit/types.js';
import { RowLevelPolicyRule, RuleExecutionContext } from '../interfaces/policyRuleInterfaces.js';
import { PermissionSetLikeMap, PolicyRuleConfig } from '../schema.js';
import { PermissionRiskLevelPresets, PolicyRiskLevel } from '../types.js';

type ProfileIterable = {
  name: string;
  preset: string;
};

type ProfileMetadata = {
  Name: string;
  Metadata: Profile;
};

export default class EnforceClassificationPresets implements RowLevelPolicyRule {
  private profilesList = new Array<ProfileIterable>();

  public constructor(private config: PolicyRuleConfig, private profiles?: PermissionSetLikeMap) {
    if (this.profiles) {
      this.profilesList = Object.entries(this.profiles).map(([profileName, profileDef]) => ({
        name: profileName,
        preset: profileDef.preset,
      }));
    }
  }

  public async run(context: RuleExecutionContext): Promise<PolicyRuleExecutionResult> {
    // was brauche ich?
    //    die rule config
    //    die policy config -> macht sinn, das jeweils in der Rule zu verarbeiten
    //    weil dann nur die Rule wissen muss, was sie braucht und Framework einfach
    //    die policy durchschleift
    // konkret für diese policy
    //    Jedes Profil mit seinem preset
    // const profileResult = Array<Promise<QueryResult<>>();
    const result = {
      ruleName: 'EnforceClassificationPresets',
      isCompliant: true,
      violations: new Array<PolicyRuleViolation>(),
      mutedViolations: [],
      warnings: [],
      errors: [],
    };
    const profileQueryResults = Array<Promise<QueryResult<ProfileMetadata>>>();
    for (const profile of this.profilesList) {
      const qr = Promise.resolve(
        context.targetOrgConnection.tooling.query<ProfileMetadata>(
          `SELECT Name,Metadata FROM Profile WHERE Name = '${profile.name}'`
        )
      );
      profileQueryResults.push(qr);
    }
    const queryResults = await Promise.all(profileQueryResults);
    const profileMetadata: ProfileMetadata[] = [];
    queryResults.forEach((qr) => {
      if (qr.records && qr.records.length > 0) {
        profileMetadata.push(qr.records[0]);
      }
    });
    profileMetadata.forEach((profile) => {
      const resolvedPreset = this.profiles![profile.Name].preset;
      if (resolvedPreset && resolvedPreset !== PermissionRiskLevelPresets.UNKNOWN) {
        // console.log(`Resolved Profile "${profile.Name}" as ${resolvedPreset}`);
        profile.Metadata.userPermissions.forEach((userPerm) => {
          const classifiedUserPerm = context.auditConfig.classifications.userPermissions?.permissions[userPerm.name];
          if (classifiedUserPerm && classifiedUserPerm.classification !== PolicyRiskLevel.UNKNOWN) {
            // console.log(classifiedUserPerm);
            if (classifiedUserPerm.classification === PolicyRiskLevel.BLOCKED) {
              result.violations.push({
                identifier: `${profile.Name}.${userPerm.name}`,
                message: 'My first violation!',
              });
            }
          }
        });
      }

      // identify profile preset
      // iterate each userPermission in profile
      // compare, if it is allowed in preset
      // create a rule violation for each preset NOT allowed
    });
    return result;
  }
}
