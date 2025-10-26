import { PathLike, readFileSync } from 'node:fs';
import { Connection } from '@salesforce/core';
import { ComponentSet, RetrieveResult } from '@salesforce/source-deploy-retrieve';
import { XMLParser } from 'fast-xml-parser';
import { ConnectedAppSettings, PermissionSet } from '@jsforce/jsforce-node/lib/api/metadata.js';

// class MetadataCache {
//   private components: Record<string, Metadata> = {};

//   public isCached(cmpName: string): boolean {
//     return this.components[cmpName] !== undefined && this.components[cmpName] !== null;
//   }
// }

export default class MDAPI {
  public constructor(private connection: Connection) {}

  /**
   * Resolves one of the pre-configured metadata types and returns
   * a map of resolved names and entire XML content of source file body.
   *
   * @param typeName
   * @param componentNames
   * @returns
   */
  public async resolve<K extends keyof typeof NamedTypesRegistry>(
    typeName: keyof typeof NamedTypesRegistry,
    componentNames: string[]
  ): Promise<NamedReturnTypes[K]> {
    const retriever = NamedTypesRegistry[typeName];
    const results = await retriever.resolve(this.connection, componentNames);
    return results as NamedReturnTypes[K];
  }

  /**
   * Resolves one of the pre-configured metadata types and returns
   * the entire XML content of source file body.
   *
   * @param typeName
   * @returns
   */
  public async resolveSingleton<K extends keyof typeof SingletonRegistry>(
    typeName: keyof typeof SingletonRegistry
  ): Promise<SingletonReturnTypes[K]> {
    const retriever = SingletonRegistry[typeName];
    const results = await retriever.resolve(this.connection);
    return results as SingletonReturnTypes[K];
  }
}

type MetadataRegistryEntryOpts<Type, Key extends keyof Type> = {
  /**
   * Metadata API name of the type.
   */
  retrieveType: string;
  /**
   * Optional XML parser instance. Typically used to fix errors for
   * properties that must be parsed as list.
   */
  parser?: XMLParser;
  /**
   * Name of the root node in XML file content
   */
  rootNodeName: Key;
  /**
   * Post processor function that sanitises the XML parse result
   */
  parsePostProcessor?: (parseResult: Type[Key]) => Type[Key];
};

abstract class MetadataRegistryEntry<Type, Key extends keyof Type> {
  public parser: XMLParser;
  public retrieveType: string;
  public rootNodeName: Key;

  public constructor(private opts: MetadataRegistryEntryOpts<Type, Key>) {
    this.retrieveType = this.opts.retrieveType;
    this.parser = this.opts.parser ?? new XMLParser();
    this.rootNodeName = this.opts.rootNodeName;
  }

  public parse(fullFilePath: PathLike): Type[Key] {
    const fileContent = readFileSync(fullFilePath, 'utf-8');
    const parsedContent = this.parser.parse(fileContent) as Type;
    if (this.opts.parsePostProcessor) {
      return this.opts.parsePostProcessor(parsedContent[this.rootNodeName]);
    }
    return parsedContent[this.rootNodeName];
  }
}

/**
 * The entry is a type that only has one single instance on the org, such as
 * a Setting. The component is retrieved by its root node name
 * (e.g. ConnectedAppSettings, AccountSettings, etc).
 */
class SingletonMetadata<Type, Key extends keyof Type> extends MetadataRegistryEntry<Type, Key> {
  public retrieveName: string;
  public constructor(opts: MetadataRegistryEntryOpts<Type, Key>) {
    super(opts);
    this.retrieveName = String(this.rootNodeName);
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
    return this.parseSourceFile(retrieveResult.components);
  }

  private parseSourceFile(componentSet: ComponentSet): Type[Key] {
    const cmps = componentSet.getSourceComponents().toArray();
    if (cmps.length > 0 && cmps[0].xml) {
      return this.parse(cmps[0].xml);
    }
    throw new Error('Failed to resolve settings for: ' + this.retrieveName);
  }
}

class NamedMetadata<Type, Key extends keyof Type> extends MetadataRegistryEntry<Type, Key> {
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
    return this.parseSourceFiles(retrieveResult.components);
  }

  private parseSourceFiles(componentSet: ComponentSet): Record<string, Type[Key]> {
    const cmps = componentSet.getSourceComponents().toArray();
    const result: Record<string, Type[Key]> = {};
    cmps.forEach((sourceComponent) => {
      if (sourceComponent.xml) {
        result[sourceComponent.name] = this.parse(sourceComponent.xml);
      }
    });
    return result;
  }
}

async function retrieve(compSet: ComponentSet, con: Connection): Promise<RetrieveResult> {
  const retrieveRequest = await compSet.retrieve({
    usernameOrConnection: con,
    output: '.jsc/retrieves',
  });
  const retrieveResult = await retrieveRequest.pollStatus();
  return retrieveResult;
}

export const NamedTypesRegistry = {
  PermissionSet: new NamedMetadata<PermissionSetXml, 'PermissionSet'>({
    retrieveType: 'PermissionSet',
    rootNodeName: 'PermissionSet',
    parser: new XMLParser({
      isArray: (jpath): boolean =>
        ['userPermissions', 'fieldPermissions', 'customPermissions', 'classAccesses'].includes(jpath),
    }),
    parsePostProcessor: (parseResult): PermissionSet => ({
      ...parseResult,
      userPermissions: parseResult.userPermissions ?? [],
      customPermissions: parseResult.customPermissions ?? [],
      classAccesses: parseResult.classAccesses ?? [],
    }),
  }),
};

export const SingletonRegistry = {
  ConnectedAppSettings: new SingletonMetadata<ConnectedAppSettingsXml, 'ConnectedAppSettings'>({
    rootNodeName: 'ConnectedAppSettings',
    retrieveType: 'Settings',
  }),
};

type NamedReturnTypes = {
  [K in keyof typeof NamedTypesRegistry]: Awaited<ReturnType<(typeof NamedTypesRegistry)[K]['resolve']>>;
};

type SingletonReturnTypes = {
  [K in keyof typeof SingletonRegistry]: Awaited<ReturnType<(typeof SingletonRegistry)[K]['resolve']>>;
};

type PermissionSetXml = {
  PermissionSet: PermissionSet;
};

type ConnectedAppSettingsXml = {
  ConnectedAppSettings: ConnectedAppSettings;
};
