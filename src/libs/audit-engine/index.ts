import AuditRun from './auditRun.js';
import FileManager from './file-manager/fileManager.js';
import { AuditConfigShape } from './registry/definitions.js';

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

export function startAuditRun(directoryPath: string): AuditRun {
  const loadedConfig = ConfigFileManager.parse(directoryPath);
  return new AuditRun(loadedConfig);
}
