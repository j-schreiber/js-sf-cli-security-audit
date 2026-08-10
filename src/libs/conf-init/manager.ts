import { AuditRunConfig, Inventories } from '../audit-engine/index.js';
import SfConnection from '../../salesforce/connection.js';
import { InventoryInitialisers } from './defaultClassifications.js';

export type InventoryManageOptions = {
  /** Inventory type to manage */
  type: Inventories;
  /** Perform a prune operation (delete local entities not on org) */
  prune: boolean;
  /** Perform a refresh operation (add missing local entities from org) */
  refresh: boolean;
  /** The existing config that will be updated in the process */
  config: AuditRunConfig;
};

export type ManageInventoryResult = {
  addedEntities: string[];
  removedEntities: string[];
  updatedConfig: AuditRunConfig;
  type: Inventories;
};

type InventoryOf<I extends Inventories> = Awaited<ReturnType<(typeof InventoryInitialisers)[I]>>;

export default class AuditConfigProvider {
  /**
   * Updates the defined inventory type with the specific operation
   * of the supplied audit config and in-memory.
   *
   * @param targetOrg
   * @param opts
   */
  public static async manageInventory(
    targetOrg: SfConnection,
    opts: InventoryManageOptions
  ): Promise<ManageInventoryResult> {
    const freshInventory = await loadInventory(opts.type, targetOrg);
    const workingInventory = opts.config.inventory[opts.type] ?? {};
    const result: ManageInventoryResult = {
      type: opts.type,
      updatedConfig: opts.config,
      addedEntities: [],
      removedEntities: [],
    };
    if (opts.refresh) {
      for (const [entityName, entity] of Object.entries(freshInventory)) {
        if (!workingInventory[entityName]) {
          workingInventory[entityName] = entity;
          result.addedEntities.push(entityName);
        }
      }
    }
    if (opts.prune) {
      for (const entityName of Object.keys(workingInventory)) {
        if (!freshInventory[entityName]) {
          delete workingInventory[entityName];
          result.removedEntities.push(entityName);
        }
      }
    }
    result.updatedConfig.inventory[opts.type] = workingInventory;
    return result;
  }
}

async function loadInventory<I extends Inventories>(type: I, con: SfConnection): Promise<InventoryOf<I>> {
  const initialiser = InventoryInitialisers[type];
  const freshInventory = await initialiser(con);
  return freshInventory as unknown as InventoryOf<I>;
}
