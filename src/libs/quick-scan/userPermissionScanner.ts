import { EventEmitter } from 'node:events';
import { Connection } from '@salesforce/core';
import { Profile, PermissionSet as PermissionSetMetadata } from '@jsforce/jsforce-node/lib/api/metadata.js';
import MDAPI from '../core/mdapi/mdapiRetriever.js';
import { PERMISSION_SETS_QUERY, PROFILES_QUERY } from '../core/constants.js';
import { PermissionSet } from '../policies/salesforceStandardTypes.js';
import { QuickScanOptions, QuickScanResult } from './types.js';

type ScannedEntities = {
  profiles: Record<string, Profile>;
  permissionSets: Record<string, PermissionSetMetadata>;
};

export type ScanStatusEvent = {
  profiles: EntityScanStatus;
  permissionSets: EntityScanStatus;
  users: EntityScanStatus;
  status: 'Pending' | 'In Progress' | 'Completed';
};

export type EntityScanStatus = {
  total?: number;
  resolved?: number;
  status?: string;
};

export default class UserPermissionScanner extends EventEmitter {
  private status: ScanStatusEvent = {
    profiles: {},
    permissionSets: {},
    users: {},
    status: 'Pending',
  };

  public constructor() {
    super();
  }

  public async quickScan(opts: QuickScanOptions): Promise<QuickScanResult> {
    this.emitProgress({ status: 'Pending' });
    const scannedEntities = await this.resolveEntities(opts.targetOrg);
    const scanResult: QuickScanResult = {
      permissions: {},
      scannedProfiles: Object.keys(scannedEntities.profiles),
      scannedPermissionSets: Object.keys(scannedEntities.permissionSets),
    };
    opts.permissions.forEach((permName) => {
      const profiles = findGrantingEntities(permName, scannedEntities.profiles);
      const permissionSets = findGrantingEntities(permName, scannedEntities.permissionSets);
      scanResult.permissions[permName] = { permissionSets, profiles };
    });
    this.emitProgress({ status: 'Completed' });
    return scanResult;
  }

  private async resolveEntities(targetOrg: Connection): Promise<ScannedEntities> {
    const promises: Array<Promise<unknown>> = [];
    this.emitProgress({ status: 'In Progress' });
    promises.push(this.resolveProfiles(targetOrg));
    promises.push(this.resolvePermissionSets(targetOrg));
    const resolvedEntities = await Promise.all(promises);
    return {
      profiles: resolvedEntities[0] as Record<string, Profile>,
      permissionSets: resolvedEntities[1] as Record<string, PermissionSetMetadata>,
    };
  }

  private async resolveProfiles(targetOrg: Connection): Promise<Record<string, Profile>> {
    const profiles = await targetOrg.query<PermissionSet>(PROFILES_QUERY);
    this.emitProgress({ profiles: { total: profiles.records.length, resolved: 0 } });
    const mdapi = MDAPI.create(targetOrg);
    const resolved = await mdapi.resolve(
      'Profile',
      profiles.records.map((permsetRecord) => permsetRecord.Profile.Name)
    );
    this.emitProgress({ profiles: { resolved: Object.keys(resolved).length } });
    return resolved;
  }

  private async resolvePermissionSets(targetOrg: Connection): Promise<Record<string, PermissionSetMetadata>> {
    const permSets = await targetOrg.query<PermissionSet>(PERMISSION_SETS_QUERY);
    this.emitProgress({ permissionSets: { total: permSets.records.length, resolved: 0 } });
    const mdapi = MDAPI.create(targetOrg);
    const resolved = await mdapi.resolve(
      'PermissionSet',
      permSets.records.map((permsetRecord) => permsetRecord.Name)
    );
    this.emitProgress({ permissionSets: { resolved: Object.keys(resolved).length } });
    return resolved;
  }

  private emitProgress(update: Partial<ScanStatusEvent>): void {
    this.status.profiles = { ...this.status.profiles, ...update.profiles };
    this.status.permissionSets = { ...this.status.permissionSets, ...update.permissionSets };
    this.status.users = { ...this.status.users, ...update.users };
    this.status.status = update.status ?? this.status.status;
    this.emit('progress', structuredClone(this.status));
  }
}

function findGrantingEntities(
  permName: string,
  resolvedEntities: Record<string, Profile | PermissionSetMetadata>
): string[] {
  const entities = new Set<string>();
  Object.entries(resolvedEntities).forEach(([entityName, metadata]) => {
    const userPerms = metadata.userPermissions.map((userPerm) => userPerm.name);
    if (userPerms.includes(permName)) {
      entities.add(entityName);
    }
  });
  return Array.from(entities);
}
