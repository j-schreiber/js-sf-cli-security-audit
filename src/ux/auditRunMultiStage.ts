import { MultiStageOutput, MultiStageOutputOptions } from '@oclif/multi-stage-output';
import { Org } from '@salesforce/core';
import { AuditRunConfigPolicies, BasePolicyFileContent, ConfigFile } from '../libs/config/audit-run/schema.js';

export const LOAD_AUDIT_CONFIG = 'Loading audit config';
export const RESOLVE_POLICIES = 'Resolving policies';
export const EXECUTE_RULES = 'Executing rules';
export const FINALISE = 'Formatting results';

type AuditRunStageOptions = {
  targetOrg: Org;
  directoryRootPath: string;
};

export default class AuditRunMultiStageOutput {
  public mso: MultiStageOutput<AuditRunData>;
  private stageSpecificBlocks;

  public constructor(opts: MultiStageOutputOptions<AuditRunData>) {
    this.stageSpecificBlocks = opts.stageSpecificBlock;
    this.mso = new MultiStageOutput<AuditRunData>(opts);
  }
  /**
   * This pattern allows to stub multi-stage outputs in tests to mute output
   * to stdout during test execution.
   *
   * In your code, create a new instance like this
   * ```
   * const ms = AuditRunMultiStageOutput.create(sobj, flags.json);
   * ```
   *
   * @param opts
   * @param jsonEnabled
   * @returns
   */
  public static create(opts: AuditRunStageOptions, jsonEnabled?: boolean): AuditRunMultiStageOutput {
    const targetOrg = opts.targetOrg.getUsername() ?? opts.targetOrg.getOrgId();
    return new AuditRunMultiStageOutput({
      jsonEnabled: jsonEnabled ?? false,
      stages: [LOAD_AUDIT_CONFIG, RESOLVE_POLICIES, EXECUTE_RULES, FINALISE],
      title: 'Auditing Org',
      preStagesBlock: [
        {
          type: 'message',
          get: () => `Auditing ${targetOrg} with config from ${opts.directoryRootPath}`,
        },
      ],
      postStagesBlock: [
        {
          type: 'static-key-value',
          label: 'Status',
          get: (data) => data?.currentStatus,
        },
      ],
      stageSpecificBlock: [],
    });
  }

  public start(): void {
    this.mso.goto(LOAD_AUDIT_CONFIG, { currentStatus: 'Initialising' });
  }

  public startPolicies(policies: AuditRunConfigPolicies): void {
    this.mso.goto(RESOLVE_POLICIES, { currentStatus: 'Resolving' });
    Object.entries(policies).forEach(([policyName, policy]) => {
      const policyDef = policy as ConfigFile<BasePolicyFileContent>;
      this.stageSpecificBlocks!.push({
        stage: RESOLVE_POLICIES,
        type: 'message',
        get: () => `Resolve entities for ${policyName}`,
      });
      if (policyDef.content.rules && Object.keys(policyDef.content.rules).length > 0) {
        this.stageSpecificBlocks!.push({
          stage: EXECUTE_RULES,
          type: 'message',
          get: () => `Execute ${Object.keys(policyDef.content.rules).length} rule(s) for ${policyName}`,
        });
      }
      this.mso.updateData({});
    });
  }

  public startRuleExecution(): void {
    this.mso.goto(EXECUTE_RULES, { currentStatus: 'Executing' });
  }

  public finish(): void {
    this.mso.goto(FINALISE, { currentStatus: 'Completed' });
    this.mso.stop('completed');
  }
}

export type AuditRunData = {
  policies: string[];
  enabledRulesInPolicy: string[];
  currentStatus: string;
};
