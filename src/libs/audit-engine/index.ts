import FileManager from './file-manager/fileManager.js';
import { AuditConfigShape } from './registry/shape/auditConfigShape.js';

export { default as AuditRun, startAuditRun } from './auditRun.js';
export type { AuditRunConfig } from './registry/shape/auditConfigShape.js';

export const ConfigFileManager = new FileManager(AuditConfigShape);
