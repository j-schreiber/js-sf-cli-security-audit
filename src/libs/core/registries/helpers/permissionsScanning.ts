import { Messages } from '@salesforce/core';
import { Profile } from '@jsforce/jsforce-node/lib/api/metadata.js';
import { AuditRunConfig, NamedPermissionsClassification, PermissionsClassification } from '../../file-mgmt/schema.js';
import { ClassificationNames } from '../../policyRegistry.js';
import { PolicyRuleViolation, RuleComponentMessage } from '../../result-types.js';
import { PermissionRiskLevel } from '../../classification-types.js';
import { permissionAllowedInPreset } from '../../policy-types.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.enforceClassificationPresets');

export type ResolvedProfileLike = {
  name: string;
  preset: string;
  metadata: PartialProfileLike;
};

export type ScanResult = {
  violations: PolicyRuleViolation[];
  warnings: RuleComponentMessage[];
};

export type PartialProfileLike = Pick<Profile, 'userPermissions' | 'customPermissions'>;

type PermissionsListKey = keyof PartialProfileLike;

/**
 * Scan userPermissions and customPermissions of a profile or permission set and
 * get a unified scan result with violations (risk level not allowed) and warnings
 * (risk level not classified)
 *
 * @param profileLike
 * @param auditRun
 * @param rootIdentifier Optional root identifier for messages to prepend.
 * @returns
 */
export function scanProfileLike(
  profileLike: ResolvedProfileLike,
  auditRun: AuditRunConfig,
  rootIdentifier?: string[]
): ScanResult {
  if (!profileLike.metadata) {
    return { violations: [], warnings: [] };
  }
  const userPermsResult = scanPermissions(profileLike, 'userPermissions', auditRun, rootIdentifier);
  const customPermsResult = scanPermissions(profileLike, 'customPermissions', auditRun, rootIdentifier);
  userPermsResult.violations.push(...customPermsResult.violations);
  userPermsResult.warnings.push(...customPermsResult.warnings);
  return userPermsResult;
}

export function scanPermissions(
  profile: ResolvedProfileLike,
  permissionListName: PermissionsListKey,
  auditRun: AuditRunConfig,
  rootIdentifier?: string[]
): ScanResult {
  const result: ScanResult = { warnings: [], violations: [] };
  for (const perm of profile.metadata[permissionListName]) {
    const identifier = rootIdentifier ? [...rootIdentifier, profile.name, perm.name] : [profile.name, perm.name];
    const permClassification = resolvePerm(perm.name, auditRun, permissionListName);
    if (permClassification) {
      if (permClassification.classification === PermissionRiskLevel.BLOCKED) {
        result.violations.push({
          identifier,
          message: messages.getMessage('violations.permission-is-blocked'),
        });
      } else if (!permissionAllowedInPreset(permClassification.classification, profile.preset)) {
        result.violations.push({
          identifier,
          message: messages.getMessage('violations.classification-preset-mismatch', [
            permClassification.classification,
            profile.preset,
          ]),
        });
      } else if (permClassification.classification === PermissionRiskLevel.UNKNOWN) {
        result.warnings.push({
          identifier,
          message: messages.getMessage('warnings.permission-unknown'),
        });
      }
    } else {
      result.warnings.push({
        identifier,
        message: messages.getMessage('warnings.permission-not-classified'),
      });
    }
  }
  return result;
}

export function resolvePerm(
  permName: string,
  auditRun: AuditRunConfig,
  type: ClassificationNames
): NamedPermissionsClassification | undefined {
  return nameClassification(permName, auditRun.classifications[type]?.content.permissions[permName]);
}

function nameClassification(
  permName: string,
  perm?: PermissionsClassification
): NamedPermissionsClassification | undefined {
  return perm ? { name: permName, ...perm } : undefined;
}
