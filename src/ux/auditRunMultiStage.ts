import { MultiStageOutput } from '@oclif/multi-stage-output';
import { Org } from '@salesforce/core';

export const LOAD_AUDIT_CONFIG = 'Load Audit Config';
export const RESOLVE_POLICIES = 'Resolve Policies';
export const EXECUTE_RULES = 'Execute Rules';
export const FINALISE = 'Format Results';

type AuditRunStageOptions = {
  targetOrg: Org;
  directoryRootPath: string;
};

export default class AuditRunMultiStageOutput {
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
  public static create(opts: AuditRunStageOptions, jsonEnabled?: boolean): MultiStageOutput<MultiStageData> {
    const targetOrg = opts.targetOrg.getUsername() ?? opts.targetOrg.getOrgId();
    return new MultiStageOutput<MultiStageData>({
      jsonEnabled: jsonEnabled ?? false,
      stages: [LOAD_AUDIT_CONFIG, RESOLVE_POLICIES, EXECUTE_RULES, FINALISE],
      title: `${targetOrg} (${opts.directoryRootPath})`,
    });
  }
}

export type MultiStageData = {
  fieldCount: string;
  totalRecords: string;
  fieldsUnderAnalysis: string;
  skippedFields: string;
  describeStatus: string;
  analyseDefaults: boolean;
  analyseHistory: boolean;
  segmentRecordTypes: boolean;
  totalQueries: number;
  totalRecordTypes: string;
};
