import { Connection } from '@salesforce/core';
import { ComponentSet } from '@salesforce/source-deploy-retrieve';
import MetadataRegistryEntry, {
  ComponentRetrieveResult,
  MetadataRegistryEntryOpts,
  retrieve,
} from './metadataRegistryEntry.js';

/**
 * The entry is a typical named metadata that is organized in a dedicated source folder
 * where all entities have the same format. The components are retrieved and organized
 * by their developer name.
 */
export default class NamedMetadata<Type, Key extends keyof Type> extends MetadataRegistryEntry<Type, Key> {
  public constructor(opts: MetadataRegistryEntryOpts<Type, Key>) {
    super(opts);
  }
  /**
   * Resolves component names, retrieves the metadata and returns
   * as a strongly typed result.
   *
   * @param con
   * @param componentNames
   * @returns
   */
  public async resolve(con: Connection, componentNames: string[]): Promise<Record<string, Type[Key]>> {
    const cmpSet = new ComponentSet(componentNames.map((cname) => ({ type: this.retrieveType, fullName: cname })));
    const retrieveResult = await retrieve(cmpSet, con);
    const resolvedFiles = this.parseSourceFiles(retrieveResult.retrievedComponents, componentNames);
    return resolvedFiles;
  }

  private parseSourceFiles(
    components: ComponentRetrieveResult['retrievedComponents'],
    requestedNames: string[]
  ): Record<string, Type[Key]> {
    const result: Record<string, Type[Key]> = {};
    for (const requestedName of requestedNames) {
      const retrievedType = components[this.retrieveType]?.[requestedName];
      if (retrievedType?.filePath) {
        // the available method parseXmlSync on source component does not
        // resolve the "rootNodeProblem" from XML. Therefore, we implement
        // our own method to parse and return the "inner xml".
        const contents = this.extract(retrievedType.fileContent);
        if (contents) {
          result[retrievedType.identifier] = contents;
        }
      }
    }
    return result;
  }
}
