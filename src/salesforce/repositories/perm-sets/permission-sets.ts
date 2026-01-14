import EventEmitter from 'node:events';
import { Connection } from '@salesforce/core';
import MDAPI from '../../mdapi/mdapi.js';
import { PermissionSet, SfPermissionSet } from '../perm-sets/perm-sets.types.js';
import { ResolvePermSetOptions, ResolvePermSetOptionsSchema } from './perm-sets.types.js';
import { PERMISSION_SETS_QUERY } from './queries.js';

export default class PermissionSets extends EventEmitter {
  private readonly mdapi: MDAPI;

  public constructor(private readonly con: Connection) {
    super();
    this.mdapi = MDAPI.create(this.con);
  }

  public async resolve(opts?: Partial<ResolvePermSetOptions>): Promise<Map<string, PermissionSet>> {
    const defOpts = ResolvePermSetOptionsSchema.parse(opts ?? {});
    const allPermsets = await this.retrievePermsetsFromOrg();
    const permsetsToRetrieve = defOpts.filterNames ? defOpts.filterNames : Array.from(allPermsets.keys());
    this.emit('entityresolve', { total: permsetsToRetrieve.length, resolved: 0 });
    const resolvedPermsets = defOpts.withMetadata ? await this.mdapi.resolve('PermissionSet', permsetsToRetrieve) : {};
    const results = new Map<string, PermissionSet>();
    for (const permsetName of permsetsToRetrieve) {
      const permsetRecord = allPermsets.get(permsetName);
      const permsetMdata = resolvedPermsets[permsetName];
      if (!(permsetRecord && ((defOpts.withMetadata && permsetMdata) || !defOpts.withMetadata))) {
        continue;
      }
      if (defOpts.isCustomOnly && !permsetRecord.IsCustom) {
        continue;
      }
      results.set(permsetName, {
        metadata: permsetMdata,
        isCustom: permsetRecord.IsCustom ?? true,
        name: permsetName,
      });
    }
    this.emit('entityresolve', { total: permsetsToRetrieve.length, resolved: results.size });
    return results;
  }

  private async retrievePermsetsFromOrg(): Promise<Map<string, SfPermissionSet>> {
    const permsets = await this.con.query<SfPermissionSet>(PERMISSION_SETS_QUERY);
    return new Map(permsets.records.map((permset) => [permset.Name, permset]));
  }
}
