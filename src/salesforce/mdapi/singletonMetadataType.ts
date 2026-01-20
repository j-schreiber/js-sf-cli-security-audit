import { Connection, Messages } from '@salesforce/core';
import { ComponentSet } from '@salesforce/source-deploy-retrieve';
import MetadataRegistryEntry, {
  ComponentRetrieveResult,
  MetadataRegistryEntryOpts,
  retrieve,
} from './metadataRegistryEntry.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'metadataretrieve');

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
    const result = await retrieve(cmpSet, con);
    return this.returnRetrieveType(result.retrievedComponents);
  }

  private returnRetrieveType(components: ComponentRetrieveResult['retrievedComponents']): Type[Key] {
    if (components.length > 0) {
      const rawFileContent = components[0].fileContent;
      return this.extract(rawFileContent);
    }
    throw messages.createError('error.FailedToRetrieveComponent', [`${this.retrieveName}.${this.retrieveType}`]);
  }
}
