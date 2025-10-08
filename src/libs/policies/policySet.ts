import { PermissionsClassification, PermSetsPolicyConfig, ProfilesPolicyConfig } from './schema.js';
import { PolicyRiskLevel } from './types.js';

/**
 * A full audit config
 */
export default class PolicySet {
  public classification: AuditClassifications;
  public policies: AuditPolicies;

  public constructor() {
    this.classification = new AuditClassifications();
    this.policies = new AuditPolicies();
  }

  public sort(): void {
    this.classification.userPermissions.sort(
      (a, b) => getRiskLevelOrdinalValue(a.classification) - getRiskLevelOrdinalValue(b.classification)
    );
    this.classification.customPermissions.sort(
      (a, b) => getRiskLevelOrdinalValue(a.classification) - getRiskLevelOrdinalValue(b.classification)
    );
  }
}

function getRiskLevelOrdinalValue(value: string): number {
  return Object.keys(PolicyRiskLevel).indexOf(value.toUpperCase());
}

export class AuditClassifications {
  public userPermissions: PermissionsClassification[];
  public customPermissions: PermissionsClassification[];

  public constructor() {
    this.userPermissions = [];
    this.customPermissions = [];
  }
}

export class AuditPolicies {
  public profiles?: ProfilesPolicyConfig;
  public permissionSets?: PermSetsPolicyConfig;

  public constructor() {}
}
