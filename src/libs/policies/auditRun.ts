// import fs from 'node:fs';
import { Connection } from '@salesforce/core';
import { AuditPolicyResult, AuditResult } from '../audit/types.js';
import AuditRunConfig from './interfaces/auditRunConfig.js';
import ProfilePolicy from './profilePolicy.js';
import Policy from './policy.js';
import PermissionSetPolicy from './permissionSetPolicy.js';
import AuditRunConfigInitialiser from './auditRunConfigInitialiser.js';

type ResultsMap = Record<string, AuditPolicyResult>;
type PolicyMap = Record<string, Policy>;

type InitOptions = {
  directoryPath: string;
  refreshDefinitions?: boolean;
  mergeFiles?: boolean;
};

/**
 * Instance of an audit run that manages high-level operations
 */
export default class AuditRun {
  public configs: AuditRunConfig;

  private constructor(directoryPath?: string) {
    this.configs = new AuditRunConfig(directoryPath);
  }

  /**
   * Loads an existing config from disk to prepare a new audit run
   *
   * @param directoryPath
   * @returns
   */
  public static load(directoryPath: string): AuditRun {
    const ps = new AuditRun(directoryPath);
    return ps;
  }

  /**
   * Initialises a new audit run config from a target org with default
   * options and writes config files to a target directory.
   *
   * @param con
   * @param options
   * @returns
   */
  public static async initialiseNewConfig(con: Connection, options: InitOptions): Promise<AuditRunConfig> {
    const result = await AuditRunConfigInitialiser.initConfigFromOrg(con);
    result.write(options.directoryPath);
    return result;
  }

  /**
   * Executes an initialised audit run instance
   *
   * @param targetOrgConnection
   * @returns
   */
  public async execute(targetOrgConnection: Connection): Promise<AuditResult> {
    // const mockResult = JSON.parse(
    //   fs.readFileSync('test/mocks/data/audit-lib-results/run/full-non-compliant.json', 'utf8')
    // ) as AuditResult;
    // return mockResult;
    const executablePolicies = resolvePolicies(this.configs);
    const results = await runPolicies(executablePolicies, targetOrgConnection);
    return {
      isCompliant: isCompliant(results),
      policies: results,
    };
  }
}

function isCompliant(results: ResultsMap): boolean {
  const list = Object.values(results);
  return list.reduce((prevVal, currentVal) => prevVal && currentVal.isCompliant, list[0].isCompliant);
}

async function runPolicies(policies: PolicyMap, targetOrgConnection: Connection): Promise<ResultsMap> {
  const resultsArray: Array<Promise<AuditPolicyResult>> = [];
  const policiesList: string[] = [];
  Object.entries(policies).forEach(([policyKey, executable]) => {
    policiesList.push(policyKey);
    resultsArray.push(executable.run({ targetOrgConnection }));
  });
  const arrayResult = await Promise.all(resultsArray);
  const results: ResultsMap = {};
  arrayResult.forEach((policyResult) => {
    const policyKey = policiesList[arrayResult.indexOf(policyResult)];
    results[policyKey] = policyResult;
  });
  return results;
}

function resolvePolicies(config: AuditRunConfig): PolicyMap {
  const pols: PolicyMap = {};
  if (config.policies.Profiles) {
    pols.Profiles = new ProfilePolicy(config.policies.Profiles.content, config);
  }
  if (config.policies.PermissionSets) {
    pols.PermissionSets = new PermissionSetPolicy(config.policies.PermissionSets.content, config);
  }
  return pols;
}
