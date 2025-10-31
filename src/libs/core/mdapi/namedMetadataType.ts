import { Connection } from '@salesforce/core';
import { ComponentSet } from '@salesforce/source-deploy-retrieve';
import MetadataRegistryEntry, { MetadataRegistryEntryOpts, retrieve } from './metadataRegistryEntry.js';

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
    return this.parseSourceFiles(retrieveResult.components, componentNames);
  }

  private parseSourceFiles(componentSet: ComponentSet, retrievedNames: string[]): Record<string, Type[Key]> {
    const cmps = componentSet.getSourceComponents().toArray();
    const result: Record<string, Type[Key]> = {};
    cmps.forEach((sourceComponent) => {
      if (sourceComponent.xml && retrievedNames.includes(sourceComponent.name)) {
        result[sourceComponent.name] = this.parse(sourceComponent.xml);
      }
    });
    return result;
  }
}
