import AuditRun from './auditRun.js';
import FileManager from './file-manager/fileManager.js';
import { AuditConfigShape, AuditRunConfig } from './registry/definitions.js';

export { default as AuditRun } from './auditRun.js';
export { AuditConfigShape } from './registry/definitions.js';
export { PermissionRiskLevel, UserPrivilegeLevel } from './registry/shape/schema.js';
export { default as RuleRegistry } from './registry/ruleRegistry.js';

export type { AuditRunConfig, Policies, Classifications } from './registry/definitions.js';
export type { PolicyConfig } from './registry/shape/schema.js';
export type { EntityResolveEvent } from './auditRun.js';
export type { AuditResult } from './registry/result.types.js';

export const ConfigFileManager = new FileManager(AuditConfigShape);
export { PolicyDefinitions, loadPolicy } from './registry/definitions.js';

/**
 * Loads audit config from directory and initialises audit run.
 *
 * @param directoryPath
 * @returns
 */
export function startAuditRun(directoryPath: string): AuditRun {
  return new AuditRun(loadAuditConfig(directoryPath));
}

/**
 * Reads audit config with default shape from directory.
 *
 * @param directoryPath
 * @returns
 */
export function loadAuditConfig(directoryPath: string): AuditRunConfig {
  return ConfigFileManager.parse(directoryPath);
}

/**
 * Saves audit config to disk and returns a save result.
 *
 * @param directoryPath
 * @param config
 * @returns
 */
export function saveAuditConfig(
  directoryPath: string,
  config: AuditRunConfig
): ReturnType<(typeof ConfigFileManager)['save']> {
  const fm = new FileManager(AuditConfigShape);
  return fm.save(directoryPath, config);
}
