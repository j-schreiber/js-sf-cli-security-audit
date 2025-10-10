import { Connection } from '@salesforce/core';
import { AuditPolicyResult, AuditResult } from '../audit/types.js';
import AuditRunConfig from './interfaces/auditRunConfig.js';
import ProfilePolicy from './profilePolicy.js';
import { Policy } from './interfaces/policyRuleInterfaces.js';

type ResultsMap = Record<string, AuditPolicyResult>;
type PolicyMap = Record<string, Policy>;
/**
 * Instance of an audit run that manages high-level operations
 */
export default class AuditRun {
  public configs: AuditRunConfig;

  private constructor(directoryPath: string) {
    this.configs = new AuditRunConfig(directoryPath);
  }

  public static load(directoryPath: string): AuditRun {
    const ps = new AuditRun(directoryPath);
    return ps;
  }

  public async execute(targetOrgConnection: Connection): Promise<AuditResult> {
    const executablePolicies = resolvePolicies(this.configs);
    const results = await runPolicies(executablePolicies, targetOrgConnection);
    return {
      isCompliant: true,
      policies: results,
    };
  }
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
  if (config.policies.profiles) {
    pols.Profiles = new ProfilePolicy(config.policies.profiles.content, config);
  }
  if (config.policies.permissionSets) {
    // orderedPolicies.push(new ProfilePolicy(config.policies.profiles.content, config))
  }
  return pols;
}
