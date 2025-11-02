import { Connection } from '@salesforce/core';

export type QuickScanResult = {
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
