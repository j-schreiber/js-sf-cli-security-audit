/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import { Connection } from '@salesforce/core';
import { AuditRunConfig, RuleRegistry, Policies, PolicyConfig, PolicyDefinitions } from '../audit-engine/index.js';
import { AuditInitPresets } from './init.types.js';
import { Initialiser, InventoryInitialisers, ShapeInitialisers } from './defaultClassifications.js';
import { DefaultPolicyDefinitions } from './defaultPolicies.js';

/**
 * Additional options how the config should be initialised.
 */
export type AuditInitOptions = {
  /**
   * An optional preset to initialise classifications and policies.
   */
  preset?: AuditInitPresets;
};

/**
 * Exposes key functionality to load an audit config as static methods. This makes
 * it easy to mock the results during tests.
 */
export default class AuditConfig {
  /**
   * Initialise a new audit config from target org and writes
   * files to the destination directory.
   *
   * @param con
   */
  public static async init(targetCon: Connection, opts?: AuditInitOptions): Promise<AuditRunConfig> {
    const conf: AuditRunConfig = { shape: {}, inventory: {}, policies: {}, acceptedRisks: {}, controls: {} };
    conf.shape = await this.initSubtype(ShapeInitialisers, targetCon, opts);
    conf.inventory = await this.initSubtype(InventoryInitialisers, targetCon, opts);
    for (const policyName of Object.keys(PolicyDefinitions)) {
      const policy = initPolicyConfig(policyName as Policies);
      conf.policies[policyName as Policies] = policy as any;
    }
    return conf;
  }

  private static async initSubtype(
    initialisable: Record<string, Initialiser>,
    targetCon: Connection,
    opts?: AuditInitOptions
  ): Promise<Record<string, unknown>> {
    const initPromises = Object.entries(initialisable).map(([, init]) => init(targetCon, opts?.preset));
    const inits = await Promise.all(initPromises);
    const result: Record<string, unknown> = {};
    const keys = Object.keys(initialisable);
    for (const initEntry of keys) {
      result[initEntry] = inits.at(keys.indexOf(initEntry));
    }
    return result;
  }
}

export function initPolicyConfig<P extends Policies>(policyName: P): (typeof PolicyDefinitions)[P]['configType'] {
  const def = PolicyDefinitions[policyName];
  const registry = new RuleRegistry(def.rules);
  const content: PolicyConfig = { enabled: true, rules: {} };
  for (const validRule of registry.registeredRules()) {
    content.rules[validRule] = {
      enabled: true,
    };
  }
  if (DefaultPolicyDefinitions[policyName]) {
    return { ...content, ...DefaultPolicyDefinitions[policyName]() };
  }
  return content;
}
