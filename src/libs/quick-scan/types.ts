import { Connection } from '@salesforce/core';

export type QuickScanResult = {
  permissions: QuickScanPermissionResult;
  scannedProfiles: string[];
  scannedPermissionSets: string[];
};

export type QuickScanPermissionResult = {
  [permissionName: string]: PermissionScanResult;
};

export type PermissionScanResult = {
  profiles: string[];
  permissionSets: string[];
};

export type QuickScanOptions = {
  targetOrg: Connection;
  permissions: string[];
};
