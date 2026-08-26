import EventEmitter from 'node:events';
import { Connection } from '@salesforce/core';
import { AuditPolicyResult, AuditResult } from '../audit-engine/registry/result.types.js';
import { OrgDescribe, ResolveLifecycle } from '../../salesforce/index.js';
import SfConnection from '../../salesforce/connection.js';
import { AuditRunConfig, Policies } from './registry/definitions.js';
import Policy from './registry/policy.js';
import { loadPolicy } from './registry/definitions.js';
import { PartialRuleResults } from './registry/context.types.js';
import AcceptedRisks from './accepted-risks/acceptedRisks.js';
import { verifyRoleDefinitions } from './registry/shape/shapeValidation.js';
import RoleManager from './registry/roles/roleManager.js';

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

export type UserMessageEvent = {
  message: string;
};

export type AuditScope = {
  policies?: string[];
};

/**
 * Instance of an audit run that manages high-level operations
 */
export default class AuditRun extends EventEmitter {
  public config: AuditRunConfig;
  private executablePolicies?: PolicyMap;

  public constructor(config: Partial<AuditRunConfig>) {
    super();
    this.config = { ...{ shape: {}, inventory: {}, policies: {}, acceptedRisks: {}, controls: {} }, ...config };
    ResolveLifecycle.on('resolvewarning', (warning) => this.emitWarning(warning.message));
  }

  /**
   * Runs an audit from config. Execution emits a series of status events.
   *
   * @param targetOrgConnection
   * @returns
   */
  public async execute(targetOrgConnection: Connection, opts?: AuditScope): Promise<AuditResult> {
    const sfCon = await SfConnection.create(targetOrgConnection);
    this.emitStageUpdate('initialising');
    const orgDescribe = await OrgDescribe.create(sfCon);
    await this.verifyAuditConfig(orgDescribe);
    this.executablePolicies = this.loadPolicies(opts?.policies);
    this.emitStageUpdate('resolving');
    await resolve(this.executablePolicies, sfCon, orgDescribe);
    this.emitStageUpdate('executing');
    const pendingResults = await runPolicies(this.executablePolicies, sfCon, orgDescribe);
    this.emitStageUpdate('finalising');
    const result = {
      orgId: targetOrgConnection.getAuthInfoFields().orgId,
      ...this.finalise(pendingResults),
    };
    this.emitStageUpdate('completed');
    return result;
  }

  /**
   * Access the currently enabled policies at runtime. This may be
   * different from the configured policy and can change accross
   * different runs (depending on the scope).
   *
   * @returns
   */
  public enabledPolicies(): PolicyMap {
    this.executablePolicies = this.executablePolicies ?? this.loadPolicies();
    const enabled: PolicyMap = {};
    for (const [policyName, policy] of Object.entries(this.executablePolicies)) {
      if (policy.config.enabled) {
        enabled[policyName] = policy;
      }
    }
    return enabled;
  }

  // PRIVATE ZONE

  private async verifyAuditConfig(orgDescribe: OrgDescribe): Promise<void> {
    if (this.config.controls.roles) {
      const rm = new RoleManager({ controls: this.config.controls, shape: this.config.shape });
      const roleWarnings = await verifyRoleDefinitions(rm.getRoleDefinitions(), orgDescribe);
      for (const warning of roleWarnings) {
        this.emitWarning(`${warning.path.join(' > ')}: ${warning.message}`);
      }
    }
  }

  private emitWarning(message: string): void {
    const warnMsg: UserMessageEvent = { message };
    this.emit('warning', warnMsg);
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

  /**
   * Load policies from config with scope and attach resolve listeners
   *
   * @param scope
   * @returns
   */
  private loadPolicies(scope?: string[]): PolicyMap {
    const pols: PolicyMap = {};
    for (const policyName of Object.keys(this.config.policies)) {
      if (scope && !scope.includes(policyName)) {
        continue;
      }
      const policy = loadPolicy(policyName as Policies, this.config);
      if (policy) {
        if (!policy.config.enabled && scope?.includes(policyName)) {
          policy.config.enabled = true;
        }
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

/**
 * Resolves entities for all policies and caches the results.
 *
 * @param targetOrgConnection
 */
async function resolve(
  enabledPolicies: PolicyMap,
  targetOrgConnection: SfConnection,
  orgDescribe: OrgDescribe
): Promise<void> {
  const resolveResultPromises = Object.values(enabledPolicies).map((executable) =>
    executable.resolve({ targetOrgConnection, orgDescribe })
  );
  await Promise.all(resolveResultPromises);
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
  targetOrgConnection: SfConnection,
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
