import { EventEmitter } from 'node:events';
import { Connection } from '@salesforce/core';
import { Profile, PermissionSet as PermissionSetMetadata } from '@jsforce/jsforce-node/lib/api/metadata.js';
import { PermissionSets, Profiles, User, Users } from '../../salesforce/index.js';
import { QuickScanOptions, QuickScanResult, UserPermissionAssignment } from './types.js';

type ScannedEntities = {
  profiles: Record<string, ProfileLikeIndex>;
  permissionSets: Record<string, ProfileLikeIndex>;
  users?: Map<string, User>;
};

type ProfileLikeIndex = {
  userPermissions: Set<string>;
  customPermissions: Set<string>;
};

type PartialProfileLike = Pick<Profile, 'userPermissions' | 'customPermissions'>;

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
    const scannedEntities = await this.resolveEntities(opts);
    const scanResult: QuickScanResult = {
      permissions: {},
      scannedProfiles: Object.keys(scannedEntities.profiles),
      scannedPermissionSets: Object.keys(scannedEntities.permissionSets),
    };
    opts.permissions.forEach((permName) => {
      const profiles = findGrantingEntities(permName, scannedEntities.profiles);
      const permissionSets = findGrantingEntities(permName, scannedEntities.permissionSets);
      const users = findPermissionAssignments(permName, scannedEntities);
      scanResult.permissions[permName] = { permissionSets, profiles, users };
    });
    this.emitProgress({ status: 'Completed' });
    return scanResult;
  }

  private async resolveEntities(opts: QuickScanOptions): Promise<ScannedEntities> {
    const promises: Array<Promise<unknown>> = [];
    this.emitProgress({ status: 'In Progress' });
    promises.push(this.resolveProfiles(opts.targetOrg));
    promises.push(this.resolvePermissionSets(opts.targetOrg));
    if (opts.deepScan) {
      const usersRepo = new Users(opts.targetOrg);
      promises.push(
        usersRepo.resolve({ withLoginHistory: false, withPermissions: true, withPermissionsMetadata: false })
      );
    }
    const resolvedPromises = await Promise.all(promises);
    const resolvedEntities: ScannedEntities = {
      profiles: prepareIndizes(resolvedPromises[0] as Record<string, PartialProfileLike>),
      permissionSets: prepareIndizes(resolvedPromises[1] as Record<string, PartialProfileLike>),
    };
    if (opts.deepScan) {
      resolvedEntities.users = resolvedPromises[2] as Map<string, User>;
    }
    return resolvedEntities;
  }

  private async resolveProfiles(targetOrg: Connection): Promise<Record<string, Profile>> {
    const profilesRepo = new Profiles(targetOrg);
    const profiles = await profilesRepo.resolve({ withMetadata: true });
    this.emitProgress({ profiles: { total: profiles.size } });
    const result: Record<string, Profile> = {};
    for (const profile of profiles.values()) {
      result[profile.name] = profile.metadata!;
    }
    this.emitProgress({ profiles: { resolved: profiles.size } });
    return result;
  }

  private async resolvePermissionSets(targetOrg: Connection): Promise<Record<string, PermissionSetMetadata>> {
    const permsetsRepo = new PermissionSets(targetOrg);
    permsetsRepo.addListener('entityresolve', (resolveEvt) =>
      this.emitProgress({ permissionSets: resolveEvt as ScanStatusEvent['permissionSets'] })
    );
    const permsets = await permsetsRepo.resolve({ withMetadata: true });
    const resolved: Record<string, PermissionSetMetadata> = {};
    for (const ps of permsets.values()) {
      resolved[ps.name] = ps.metadata!;
    }
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

function prepareIndizes(entities: Record<string, PartialProfileLike>): Record<string, ProfileLikeIndex> {
  const result: Record<string, ProfileLikeIndex> = {};
  for (const [identifier, metadata] of Object.entries(entities)) {
    result[identifier] = {
      userPermissions: new Set<string>(
        metadata.userPermissions.filter((perm) => perm.enabled).map((perm) => perm.name)
      ),
      customPermissions: new Set<string>(
        metadata.customPermissions.filter((perm) => perm.enabled).map((perm) => perm.name)
      ),
    };
  }
  return result;
}

function findPermissionAssignments(
  permName: string,
  scanContext: ScannedEntities
): UserPermissionAssignment[] | undefined {
  if (!scanContext.users) {
    return undefined;
  }
  const permAssignments: UserPermissionAssignment[] = [];
  for (const [username, userDetails] of scanContext.users.entries()) {
    const profile = scanContext.profiles[userDetails.profileName];
    if (profile && profile.userPermissions.has(permName)) {
      permAssignments.push({ username, source: userDetails.profileName, type: 'Profile' });
    }
    if (userDetails.assignments) {
      for (const permSetAss of userDetails.assignments) {
        const permSet = scanContext.permissionSets[permSetAss.permissionSetIdentifier];
        if (permSet && permSet.userPermissions.has(permName)) {
          permAssignments.push({ username, source: permSetAss.permissionSetIdentifier, type: 'Permission Set' });
        }
      }
    }
  }
  return permAssignments;
}

function findGrantingEntities(permName: string, resolvedEntities: Record<string, ProfileLikeIndex>): string[] {
  const entities = new Set<string>();
  Object.entries(resolvedEntities).forEach(([entityName, metadata]) => {
    if (metadata.userPermissions.has(permName)) {
      entities.add(entityName);
    }
  });
  return Array.from(entities);
}
