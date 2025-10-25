import { Connection } from '@salesforce/core';
import { AuditRunConfig } from '../../core/file-mgmt/schema.js';
import AuditConfigFileManager from '../../core/file-mgmt/auditConfigFileManager.js';
import { initCustomPermissions, initUserPermissions } from './permissionsClassification.js';
import { initConnectedApps, initPermissionSets, initProfiles } from './policyConfigs.js';

/**
 * Additional options how the config should be initialised.
 */
export type AuditInitOptions = {
  targetDir?: string;
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
    const fileManager = new AuditConfigFileManager();
    const conf: AuditRunConfig = { classifications: {}, policies: {} };
    conf.classifications.userPermissions = { content: await initUserPermissions(targetCon) };
    const customPerms = await initCustomPermissions(targetCon);
    if (customPerms) {
      conf.classifications.customPermissions = { content: customPerms };
    }
    conf.policies.Profiles = { content: await initProfiles(targetCon) };
    conf.policies.PermissionSets = { content: await initPermissionSets(targetCon) };
    conf.policies.ConnectedApps = { content: initConnectedApps() };
    if (opts?.targetDir) {
      fileManager.save(opts.targetDir, conf);
    }
    return conf;
  }

  /**
   * Loads an existing audit config from a source directory
   *
   * @param sourceDir
   */
  public static load(sourceDir: string): AuditRunConfig {
    const fileManager = new AuditConfigFileManager();
    return fileManager.parse(sourceDir);
  }
}
