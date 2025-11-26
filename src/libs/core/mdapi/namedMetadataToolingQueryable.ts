import { QueryResult, Record as JsForceRecord } from '@jsforce/jsforce-node';
import { Connection } from '@salesforce/core';
import { isNullish } from '../utils.js';
import { NamedMetadataResolver } from './metadataRegistryEntry.js';

export type NamedMetadataQueryableOpts<Type> = {
  /**
   * Object API name to retrieve. Must be available in tooling API
   */
  objectName: string;

  /**
   * Unique name field that is used to retrieve the object
   */
  nameField: string;

  /**
   * Post processor function that sanitises the XML parse result
   */
  parsePostProcessor?: (parseResult: Type) => Type;
};

/**
 * The entry is a typical named metadata that is organized in a dedicated source folder
 * where all entities have the same format. The components are queried from tooling API
 * and organized by their developer name.
 */
export default class NamedMetadataQueryable<Type, Key extends keyof Type> implements NamedMetadataResolver<Type[Key]> {
  public constructor(private opts: NamedMetadataQueryableOpts<Type[Key]>) {}
  /**
   * Resolves a set of component names by querying "Metadata" property from tooling API
   *
   * @param con
   * @param componentNames
   * @returns
   */
  public async resolve(con: Connection, componentNames: string[]): Promise<Record<string, Type[Key]>> {
    const pendingQueries = new Array<Promise<QueryResult<MetadataRecord<Type[Key]>>>>();
    componentNames.forEach((cname) => {
      const qr = Promise.resolve(
        con.tooling.query<MetadataRecord<Type[Key]>>(
          `SELECT ${this.opts.nameField},Metadata FROM ${this.opts.objectName} WHERE ${this.opts.nameField} = '${cname}'`
        )
      );
      pendingQueries.push(qr);
    });
    const queryResults = await Promise.all(pendingQueries);
    const resultMap: Record<string, Type[Key]> = {};
    queryResults.forEach((qr) => {
      if (qr.totalSize > 0) {
        const record = qr.records[0];
        const identifier = record[this.opts.nameField] as string;
        if (identifier && !isNullish(record.Metadata)) {
          resultMap[identifier] = this.opts.parsePostProcessor
            ? this.opts.parsePostProcessor(record.Metadata)
            : record.Metadata;
        }
      }
    });
    return resultMap;
  }
}

type MetadataRecord<MetadataType> = JsForceRecord & {
  Metadata: MetadataType;
};
