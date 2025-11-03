import { Connection } from '@salesforce/core';
import { ComponentSet } from '@salesforce/source-deploy-retrieve';
import MetadataRegistryEntry, {
  cleanRetrieveDir,
  MetadataRegistryEntryOpts,
  retrieve,
} from './metadataRegistryEntry.js';

/**
 * The entry is a type that only has one single instance on the org, such as
 * a Setting. The component is typically retrieved by a more generic name and
 * organized & cached by the explicit name.
 */
export default class SingletonMetadata<Type, Key extends keyof Type> extends MetadataRegistryEntry<Type, Key> {
  public retrieveName: string;
  public constructor(opts: MetadataRegistryEntryOpts<Type, Key>) {
    super(opts);
    this.retrieveName = opts.retrieveName ?? String(this.rootNodeName);
  }

  /**
   * Resolves component names, retrieves the metadata and returns
   * as a strongly typed result.
   *
   * @param con
   * @param componentNames
   * @returns
   */
  public async resolve(con: Connection): Promise<Type[Key]> {
    const cmpSet = new ComponentSet([{ type: this.retrieveType, fullName: this.retrieveName }]);
    const retrieveResult = await retrieve(cmpSet, con);
    const resolvedCmp = this.parseSourceFile(retrieveResult.components);
    cleanRetrieveDir(retrieveResult.getFileResponses());
    return resolvedCmp;
  }

  private parseSourceFile(componentSet: ComponentSet): Type[Key] {
    const cmps = componentSet.getSourceComponents({ type: this.retrieveType, fullName: this.retrieveName }).toArray();
    if (cmps.length > 0 && cmps[0].xml) {
      return this.parse(cmps[0].xml);
    }
    throw new Error('Failed to resolve settings for: ' + this.retrieveName);
  }
}
