import EventEmitter from 'node:events';
import { Connection } from '@salesforce/core';
import { AuditPolicyResult, AuditResult } from '../audit-engine/registry/result.types.js';
import { AuditConfigShape, AuditRunConfig, Policies } from './registry/shape/auditConfigShape.js';
import FileManager from './file-manager/fileManager.js';
import Policy, { ResolveEntityResult } from './registry/policy.js';
import { loadPolicy } from './registry/definitions.js';

type ResultsMap = Record<string, AuditPolicyResult>;
type PolicyMap = Record<string, Policy<unknown>>;

export function startAuditRun(directoryPath: string): AuditRun {
  const fm = new FileManager(AuditConfigShape);
  const loadedConfig = fm.parse(directoryPath);
  return new AuditRun(loadedConfig);
}

export type EntityResolveEvent = {
  total: number;
  resolved: number;
  policyName: string;
};

/**
 * Instance of an audit run that manages high-level operations
 */
export default class AuditRun extends EventEmitter {
  private executablePolicies?: PolicyMap;

  public constructor(public config: AuditRunConfig) {
    super();
  }

  public getExecutableRulesCount(policyName: Policies): number {
    if (this.executablePolicies?.[policyName] !== undefined) {
      return this.executablePolicies[policyName].getExecutableRules().length;
    }
    return 0;
  }

  /**
   * Loads all policies, resolves entities and caches the results.
   *
   * @param targetOrgConnection
   */
  public async resolve(targetOrgConnection: Connection): Promise<PolicyMap> {
    if (this.executablePolicies) {
      return this.executablePolicies;
    }
    this.executablePolicies = this.loadPolicies();
    const resolveResultPromises: Array<Promise<ResolveEntityResult<unknown>>> = [];
    Object.values(this.executablePolicies).forEach((executable) => {
      resolveResultPromises.push(executable.resolve({ targetOrgConnection }));
    });
    await Promise.all(resolveResultPromises);
    return this.executablePolicies;
  }

  /**
   * Executes an initialised audit run. Resolves policies entities
   * and executes all rules.
   *
   * @param targetOrgConnection
   * @returns
   */
  public async execute(targetCon: Connection): Promise<Omit<AuditResult, 'orgId'>> {
    this.executablePolicies = await this.resolve(targetCon);
    const results = await runPolicies(this.executablePolicies, targetCon);
    return {
      auditDate: new Date().toISOString(),
      isCompliant: isCompliant(results),
      policies: results,
    };
  }

  private loadPolicies(): PolicyMap {
    const pols: PolicyMap = {};
    for (const policyName of Object.keys(this.config.policies)) {
      const policy = loadPolicy(policyName as Policies, this.config);
      if (policy) {
        policy.addListener('entityresolve', (resolveStats: Omit<EntityResolveEvent, 'policyName'>) => {
          this.emit(`entityresolve-${policyName}`, { policyName, ...resolveStats });
        });
        pols[policyName] = policy;
      }
    }
    return pols;
  }
}

function isCompliant(results: ResultsMap): boolean {
  const list = Object.values(results);
  if (list.length === 0) {
    return true;
  }
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
