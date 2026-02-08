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
  users?: UserPermissionAssignment[];
};

export type UserPermissionAssignment = {
  username: string;
  source: string;
  type: 'Permission Set' | 'Profile';
};

export type QuickScanOptions = {
  targetOrg: Connection;
  permissions: string[];
  deepScan: boolean;
};
