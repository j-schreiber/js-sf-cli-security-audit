import { Connection } from '@salesforce/core';
import { AuditRunConfig, ConfigFileManager } from '../audit-engine/index.js';
import {
  initCustomPermissions,
  initPermissionSets,
  initProfiles,
  initUserPermissions,
  initUsers,
} from './permissionsClassification.js';
import { initDefaultPolicy, initSettings, initUserPolicy } from './policyConfigs.js';
import { AuditInitPresets } from './presets.js';

/**
 * Additional options how the config should be initialised.
 */
export type AuditInitOptions = {
  /**
   * When set, config files are created at the target location.
   */
  targetDir?: string;
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
    const conf: AuditRunConfig = { classifications: {}, policies: {} };
    conf.classifications.profiles = await initProfiles(targetCon);
    conf.classifications.permissionSets = await initPermissionSets(targetCon);
    conf.classifications.users = await initUsers(targetCon);
    conf.classifications.userPermissions = await initUserPermissions(targetCon, opts?.preset);
    const customPerms = await initCustomPermissions(targetCon);
    if (customPerms) {
      conf.classifications.customPermissions = customPerms;
    }
    conf.policies.profiles = initDefaultPolicy('profiles');
    conf.policies.permissionSets = initDefaultPolicy('permissionSets');
    conf.policies.users = initUserPolicy();
    conf.policies.connectedApps = initDefaultPolicy('connectedApps');
    conf.policies.settings = initSettings();
    // eslint-disable-next-line @typescript-eslint/prefer-nullish-coalescing
    if (opts?.targetDir || opts?.targetDir === '') {
      ConfigFileManager.save(opts.targetDir, conf);
    }
    return conf;
  }
}
