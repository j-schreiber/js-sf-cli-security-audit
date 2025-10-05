import { PermissionsPolicy } from './schema.js';
import { PolicyRiskLevel } from './types.js';

export default class PolicySet {
  public userPermissions: PermissionsPolicy[];
  public customPermissions: PermissionsPolicy[];

  public constructor() {
    this.userPermissions = [];
    this.customPermissions = [];
  }

  public sort(): void {
    this.userPermissions.sort(
      (a, b) => getRiskLevelOrdinalValue(a.classification) - getRiskLevelOrdinalValue(b.classification)
    );
  }
}

function getRiskLevelOrdinalValue(value: string): number {
  return Object.keys(PolicyRiskLevel).indexOf(value.toUpperCase());
}
