import { Messages } from '@salesforce/core';
import { Profile } from '@jsforce/jsforce-node/lib/api/metadata.js';
import { PolicyRuleViolation, RuleComponentMessage } from '../result.types.js';
import { AuditRunConfig } from '../definitions.js';
import { PermissionClassifications, PermissionRiskLevel, UserPrivilegeLevel } from '../shape/schema.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.enforceClassificationPresets');

export type ResolvedProfileLike = {
  name: string;
  role: string;
  metadata: PartialProfileLike;
};

export type ScanResult = {
  violations: PolicyRuleViolation[];
  warnings: RuleComponentMessage[];
};

export type PartialProfileLike = Pick<Profile, 'userPermissions' | 'customPermissions'>;

type PermissionsListKey = keyof PartialProfileLike;

/**
 * Moves the "name" from the classifications map to object prop
 */
type NamedPermissionClassification = PermissionClassifications['string'] & { name: string };

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
      } else if (!permissionAllowedInPreset(permClassification.classification, profile.role)) {
        result.violations.push({
          identifier,
          message: messages.getMessage('violations.classification-preset-mismatch', [
            permClassification.classification,
            profile.role,
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

export function resolvePresetOrdinalValue(value: string): number {
  return Object.keys(UserPrivilegeLevel).indexOf(value.toUpperCase().replace(' ', '_'));
}

export function permissionAllowedInPreset(permClassification: string, preset: string): boolean {
  // this works, as long as we are mindful when adding new risk levels and presets
  const invertedPermValue = Object.keys(PermissionRiskLevel).length - resolveRiskLevelOrdinalValue(permClassification);
  const invertedPresetValue = Object.keys(UserPrivilegeLevel).length - resolvePresetOrdinalValue(preset);
  return invertedPresetValue >= invertedPermValue;
}

function resolveRiskLevelOrdinalValue(value: string): number {
  return Object.keys(PermissionRiskLevel).indexOf(value.toUpperCase());
}

export const classificationSorter = (a: NamedPermissionClassification, b: NamedPermissionClassification): number =>
  resolveRiskLevelOrdinalValue(a.classification) - resolveRiskLevelOrdinalValue(b.classification);

function resolvePerm(
  permName: string,
  auditRun: AuditRunConfig,
  type: PermissionsListKey
): NamedPermissionClassification | undefined {
  return nameClassification(permName, auditRun.classifications[type]?.permissions[permName]);
}

function nameClassification(
  permName: string,
  perm?: PermissionClassifications['string']
): NamedPermissionClassification | undefined {
  return perm ? { name: permName, ...perm } : undefined;
}
