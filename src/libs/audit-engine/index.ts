import FileManager from './file-manager/fileManager.js';
import { AuditConfigShape } from './registry/shape/auditConfigShape.js';

export { default as AuditRun, startAuditRun } from './auditRun.js';
export { AuditConfigShape } from './registry/shape/auditConfigShape.js';
export { PermissionRiskLevel, UserPrivilegeLevel } from './registry/shape/schema.js';
export { default as RuleRegistry } from './registry/ruleRegistry.js';

export type { AuditRunConfig, Policies, Classifications } from './registry/shape/auditConfigShape.js';
export type { PolicyConfig } from './registry/shape/schema.js';
export type { EntityResolveEvent } from './auditRun.js';
export type { AuditResult } from './registry/result.types.js';

export const ConfigFileManager = new FileManager(AuditConfigShape);
export { PolicyDefinitions, loadPolicy } from './registry/definitions.js';
