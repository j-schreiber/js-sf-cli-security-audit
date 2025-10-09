import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import yaml from 'js-yaml';
import { CUSTOM_PERMISSIONS_PATH, PROFILE_POLICY_PATH, USER_PERMISSIONS_PATH } from '../config/filePaths.js';
import {
  PermissionsClassification,
  PermissionsConfig,
  PermissionsConfigSchema,
  PermSetsPolicyConfig,
  ProfilesPolicyConfig,
  ProfilesPolicyConfigSchema,
} from './schema.js';
import { PolicyRiskLevel } from './types.js';

/**
 * A full audit config that contains all policies, classifications and whitelistings
 * for a dedicated audit run.
 */
export default class PolicySet {
  public classification: AuditClassifications;
  public classifications: AuditClassifications2;
  public policies: AuditPolicies;

  public constructor() {
    this.classification = new AuditClassifications();
    this.policies = new AuditPolicies();
    this.classifications = new AuditClassifications2();
  }

  public static load(directoryPath: string): PolicySet {
    const ps = new PolicySet();
    if (existsSync(path.join(directoryPath, PROFILE_POLICY_PATH))) {
      ps.policies.profiles = ProfilesPolicyConfigSchema.parse(
        yaml.load(readFileSync(path.join(directoryPath, PROFILE_POLICY_PATH), 'utf8'))
      );
    }
    if (existsSync(path.join(directoryPath, USER_PERMISSIONS_PATH))) {
      ps.classifications.userPermissions = PermissionsConfigSchema.parse(
        yaml.load(readFileSync(path.join(directoryPath, USER_PERMISSIONS_PATH), 'utf-8'))
      );
    }
    if (existsSync(path.join(directoryPath, CUSTOM_PERMISSIONS_PATH))) {
      ps.classifications.customPermissions = PermissionsConfigSchema.parse(
        yaml.load(readFileSync(path.join(directoryPath, CUSTOM_PERMISSIONS_PATH), 'utf-8'))
      );
    }
    return ps;
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

export class AuditClassifications2 {
  public userPermissions?: PermissionsConfig;
  public customPermissions?: PermissionsConfig;

  public constructor() {}
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
