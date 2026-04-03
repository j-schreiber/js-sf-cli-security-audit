import EventEmitter from 'node:events';
import { Connection } from '@salesforce/core';
import { AuditPolicyResult, AuditResult } from '../audit-engine/registry/result.types.js';
import { OrgDescribe, ResolveLifecycle } from '../../salesforce/index.js';
import { AuditRunConfig, Policies } from './registry/definitions.js';
import Policy, { ResolveEntityResult } from './registry/policy.js';
import { loadPolicy } from './registry/definitions.js';
import { PartialRuleResults } from './registry/context.types.js';
import AcceptedRisks from './accepted-risks/acceptedRisks.js';
import { verifyRoleDefinitions } from './registry/shape/shapeValidation.js';

type ResultsMap = Record<string, AuditPolicyResult>;
type PendingPolicyResults = Record<string, PartialRuleResults>;
type PolicyMap = Record<string, Policy<unknown>>;

type AuditRunStage = 'initialising' | 'resolving' | 'executing' | 'finalising' | 'completed';

export type AuditRunStageUpdate = {
  newStage: AuditRunStage;
};

export type EntityResolveEvent = {
  total: number;
  resolved: number;
  policyName: string;
};

/**
 * Instance of an audit run that manages high-level operations
 */
export default class AuditRun extends EventEmitter {
  public config: AuditRunConfig;
  private executablePolicies?: PolicyMap;

  public constructor(config: Partial<AuditRunConfig>) {
    super();
    this.config = { ...{ classifications: {}, policies: {}, acceptedRisks: {}, definitions: {} }, ...config };
    ResolveLifecycle.on('warning', (warning) => this.emit('resolvewarning', warning));
  }

  public getExecutableRulesCount(policyName: Policies): number {
    if (this.executablePolicies?.[policyName] !== undefined) {
      return this.executablePolicies[policyName].getExecutableRules().length;
    }
    return 0;
  }

  /**
   * Runs an audit from config. Execution emits a series of status events.
   *
   * @param targetOrgConnection
   * @returns
   */
  public async execute(targetOrgConnection: Connection): Promise<AuditResult> {
    this.emitStageUpdate('initialising');
    const orgDescribe = await OrgDescribe.create(targetOrgConnection);
    this.verifyAuditConfig(orgDescribe);
    this.emitStageUpdate('resolving');
    const executablePolicies = await this.resolve(targetOrgConnection, orgDescribe);
    this.emitStageUpdate('executing');
    const pendingResults = await runPolicies(executablePolicies, targetOrgConnection, orgDescribe);
    this.emitStageUpdate('finalising');
    const result = {
      orgId: targetOrgConnection.getAuthInfoFields().orgId,
      ...this.finalise(pendingResults),
    };
    this.emitStageUpdate('completed');
    return result;
  }

  // PRIVATE ZONE

  private verifyAuditConfig(orgDescribe: OrgDescribe): void {
    if (this.config.definitions.roles) {
      const roleWarnings = verifyRoleDefinitions(this.config.definitions.roles, orgDescribe);
      for (const warning of roleWarnings) {
        this.emit('warning', { message: `${warning.path.join(' > ')}: ${warning.message}` });
      }
    }
  }

  /**
   * Loads all policies, resolves entities and caches the results.
   *
   * @param targetOrgConnection
   */
  private async resolve(targetOrgConnection: Connection, orgDescribe: OrgDescribe): Promise<PolicyMap> {
    if (this.executablePolicies) {
      return this.executablePolicies;
    }
    this.executablePolicies = this.loadPolicies();
    const resolveResultPromises: Array<Promise<ResolveEntityResult<unknown>>> = [];
    Object.values(this.executablePolicies).forEach((executable) => {
      resolveResultPromises.push(executable.resolve({ targetOrgConnection, orgDescribe }));
    });
    await Promise.all(resolveResultPromises);
    return this.executablePolicies;
  }

  /**
   * Completes partial results and returns as a full AuditResult
   *
   * @param pendingResults
   * @returns
   */
  private finalise(pendingResults: PendingPolicyResults): Omit<AuditResult, 'orgId'> {
    const finalisedResults: ResultsMap = {};
    const riskManager = new AcceptedRisks(this.config.acceptedRisks);
    for (const [policyName, pendingResult] of Object.entries(pendingResults)) {
      const policy = this.executablePolicies?.[policyName];
      if (policy) {
        finalisedResults[policyName] = policy.finalise(pendingResult, riskManager);
      }
    }
    return {
      auditDate: new Date().toISOString(),
      isCompliant: isCompliant(finalisedResults),
      policies: finalisedResults,
      acceptedRisks: riskManager.getStats(),
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

  private emitStageUpdate(newStage: AuditRunStage): void {
    const updateEvt: AuditRunStageUpdate = {
      newStage,
    };
    this.emit('stageupdate', updateEvt);
  }
}

function isCompliant(results: ResultsMap): boolean {
  const list = Object.values(results);
  if (list.length === 0) {
    return true;
  }
  return list.reduce((prevVal, currentVal) => prevVal && currentVal.isCompliant, list[0].isCompliant);
}

async function runPolicies(
  policies: PolicyMap,
  targetOrgConnection: Connection,
  orgDescribe: OrgDescribe
): Promise<PendingPolicyResults> {
  const resultsArray: Array<Promise<PartialRuleResults>> = [];
  const policiesList: string[] = [];
  Object.entries(policies).forEach(([policyKey, executable]) => {
    policiesList.push(policyKey);
    resultsArray.push(executable.executeRules({ targetOrgConnection, orgDescribe }));
  });
  const arrayResult = await Promise.all(resultsArray);
  const results: PendingPolicyResults = {};
  arrayResult.forEach((policyResult) => {
    const policyKey = policiesList[arrayResult.indexOf(policyResult)];
    results[policyKey] = policyResult;
  });
  return results;
}
