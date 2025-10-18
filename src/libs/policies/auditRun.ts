// import fs from 'node:fs';
import { Connection } from '@salesforce/core';
import { AuditPolicyResult, AuditResult } from '../audit/types.js';
import { AuditRunConfig } from '../config/audit-run/schema.js';
import ProfilePolicy from './profilePolicy.js';
import Policy from './policy.js';
import PermissionSetPolicy from './permissionSetPolicy.js';
import ConnectedAppPolicy from './connectedAppPolicy.js';
import AuditConfig from './initialisation/auditConfig.js';

type ResultsMap = Record<string, AuditPolicyResult>;
type PolicyMap = Record<string, Policy>;

export function startAuditRun(directoryPath: string): AuditRun {
  const conf = AuditConfig.load(directoryPath);
  return new AuditRun(conf);
}

/**
 * Instance of an audit run that manages high-level operations
 */
export default class AuditRun {
  public constructor(public configs: AuditRunConfig) {}

  /**
   * Executes an initialised audit run. This runs enabled policies
   * in parallel and runs all enabled rules per policy.
   *
   * @param targetOrgConnection
   * @returns
   */
  public async execute(targetCon: Connection): Promise<Omit<AuditResult, 'orgId'>> {
    const executablePolicies = resolvePolicies(this.configs);
    const results = await runPolicies(executablePolicies, targetCon);
    return {
      auditDate: new Date().toISOString(),
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
  if (config.policies.ConnectedApps) {
    pols.ConnectedApps = new ConnectedAppPolicy(config.policies.ConnectedApps.content, config);
  }
  return pols;
}
