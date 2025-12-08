import { Connection } from '@salesforce/core';
import { AuditRunConfig } from '../core/file-mgmt/schema.js';
import { DefaultFileManager } from '../core/file-mgmt/auditConfigFileManager.js';
import { initCustomPermissions, initUserPermissions } from './permissionsClassification.js';
import { initConnectedApps, initPermissionSets, initProfiles, initSettings, initUsers } from './policyConfigs.js';
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
    conf.classifications.userPermissions = { content: await initUserPermissions(targetCon, opts?.preset) };
    const customPerms = await initCustomPermissions(targetCon);
    if (customPerms) {
      conf.classifications.customPermissions = { content: customPerms };
    }
    conf.policies.profiles = { content: await initProfiles(targetCon) };
    conf.policies.permissionSets = { content: await initPermissionSets(targetCon) };
    conf.policies.users = { content: await initUsers(targetCon) };
    conf.policies.connectedApps = { content: initConnectedApps() };
    conf.policies.settings = { content: initSettings() };
    // eslint-disable-next-line @typescript-eslint/prefer-nullish-coalescing
    if (opts?.targetDir || opts?.targetDir === '') {
      DefaultFileManager.save(opts.targetDir, conf);
    }
    return conf;
  }

  /**
   * Loads an existing audit config from a source directory
   *
   * @param sourceDir
   */
  public static load(sourceDir: string): AuditRunConfig {
    return DefaultFileManager.parse(sourceDir);
  }
}
