import { MultiStageOutput, MultiStageOutputOptions } from '@oclif/multi-stage-output';
import AuditRun, { EntityResolveEvent } from '../libs/core/auditRun.js';
import { capitalize } from '../libs/core/utils.js';

export const LOAD_AUDIT_CONFIG = 'Loading audit config';
export const RESOLVE_POLICIES = 'Resolving policies';
export const EXECUTE_RULES = 'Executing rules';
export const FINALISE = 'Formatting results';

export type AuditRunStageOptions = {
  targetOrg: string;
  directoryRootPath: string;
  jsonEnabled?: boolean;
};

/**
 * This type mimics the original "StageBlockInfo" type from
 * MultiStageOutput and allows us to make test asserts.
 */
type StageBlockInfo<T> = {
  stage: string;
  type: 'dynamic-key-value' | 'static-key-value' | 'message';
  label?: string;
  get(data: T): string;
};

export default class AuditRunMultiStageOutput {
  public mso: MultiStageOutput<AuditRunData>;
  public stageSpecificBlocks: Array<StageBlockInfo<AuditRunData>>;
  private polStats: PolicyStatistics;

  public constructor(opts: MultiStageOutputOptions<AuditRunData>) {
    this.stageSpecificBlocks = opts.stageSpecificBlock as Array<StageBlockInfo<AuditRunData>>;
    this.mso = AuditRunMultiStageOutput.initUx(opts);
    this.polStats = {};
  }

  /**
   * In unit tests, we stub the actual UX class to hide output in terminal.
   *
   * @param opts
   * @returns
   */
  public static initUx(opts: MultiStageOutputOptions<AuditRunData>): MultiStageOutput<AuditRunData> {
    return new MultiStageOutput<AuditRunData>(opts);
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
  public static create(opts: AuditRunStageOptions): AuditRunMultiStageOutput {
    return new AuditRunMultiStageOutput({
      jsonEnabled: opts.jsonEnabled ?? false,
      stages: [LOAD_AUDIT_CONFIG, RESOLVE_POLICIES, EXECUTE_RULES, FINALISE],
      title: 'Auditing Org',
      preStagesBlock: [
        {
          type: 'message',
          get: () => `Auditing ${opts.targetOrg} with config from ${opts.directoryRootPath}`,
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

  public startPolicyResolve(runInstance: AuditRun): void {
    this.mso.goto(RESOLVE_POLICIES, { currentStatus: 'Resolving' });
    Object.entries(runInstance.configs.policies).forEach(([policyName, policy]) => {
      if (policy.content.enabled) {
        this.addPolicyStatsListener(policyName, runInstance);
        this.stageSpecificBlocks.push({
          stage: RESOLVE_POLICIES,
          type: 'dynamic-key-value',
          label: capitalize(policyName),
          get: (data: AuditRunData): string => {
            if (data?.policies?.[policyName]) {
              return `${data.policies[policyName].resolved ?? 0}/${data.policies[policyName].total ?? 0}`;
            } else {
              return '';
            }
          },
        });
        if (policy.content.rules && Object.keys(policy.content.rules).length > 0) {
          this.stageSpecificBlocks.push({
            stage: EXECUTE_RULES,
            type: 'message',
            get: () => `Execute ${Object.keys(policy.content.rules).length} rule(s) for ${policyName}`,
          });
        }
      }
    });
    this.mso.updateData({});
  }

  public startRuleExecution(): void {
    this.mso.goto(EXECUTE_RULES, { currentStatus: 'Executing' });
  }

  public finish(): void {
    this.mso.goto(FINALISE, { currentStatus: 'Completed' });
    this.mso.stop('completed');
  }

  private addPolicyStatsListener = (policyName: string, runInstance: AuditRun): void => {
    // multi stage output updates its entire internal state, but only "patches"
    // data one level deep (e.g. policies property is replaced entierly)
    // thats why we gather the statistics for each individual policy in a single variable
    // and then update the multi stage data with aggregated data
    runInstance.addListener(`entityresolve-${policyName}`, (data: EntityResolveEvent) => {
      if (this.polStats[policyName]) {
        if (data.resolved) {
          this.polStats[policyName].resolved = data.resolved;
        }
        if (data.total) {
          this.polStats[policyName].total = data.total;
        }
      } else {
        this.polStats[policyName] = { resolved: data.resolved ?? 0, total: data.total ?? 0 };
      }
      this.mso.updateData({ policies: structuredClone(this.polStats) });
    });
  };
}

export type AuditRunData = {
  enabledRulesInPolicy: string[];
  currentStatus: string;
  policies: PolicyStatistics;
};

type PolicyStatistics = {
  [policyName: string]: { total?: number; resolved?: number };
};
