import { Connection } from '@salesforce/core';
import { XMLParser } from 'fast-xml-parser';
import {
  ConnectedAppSettings,
  Metadata,
  PermissionSet,
  Profile as ProfileMetadata,
} from '@jsforce/jsforce-node/lib/api/metadata.js';
import NamedMetadata from './namedMetadataType.js';
import SingletonMetadata from './singletonMetadataType.js';
import NamedMetadataQueryable from './namedMetadataToolingQueryable.js';

export default class MDAPI {
  private static retrievers = new Map<string, MDAPI>();
  private cache: MetadataCache;

  public constructor(private connection: Connection) {
    this.cache = new MetadataCache();
  }

  public static create(connection: Connection): MDAPI {
    if (!this.retrievers.has(connection.instanceUrl)) {
      this.retrievers.set(connection.instanceUrl, new MDAPI(connection));
    }
    return this.retrievers.get(connection.instanceUrl)!;
  }

  /**
   * Resolves one of the pre-configured metadata types and returns
   * a map of resolved names and entire XML content of source file body.
   *
   * @param typeName
   * @param componentNames
   * @returns
   */
  public async resolve<K extends keyof typeof NamedTypesRegistry>(
    typeName: K,
    componentNames: string[]
  ): Promise<NamedReturnTypes[K]> {
    const retriever = NamedTypesRegistry[typeName];
    const { toRetrieve, cached } = this.fetchCached(componentNames);
    if (toRetrieve.length > 0) {
      const retrieveResults = await retriever.resolve(this.connection, toRetrieve);
      this.cacheResults(retrieveResults);
      return {
        ...cached,
        ...retrieveResults,
      } as NamedReturnTypes[K];
    }
    return cached as NamedReturnTypes[K];
  }

  /**
   * Resolves one of the pre-configured metadata types and returns
   * the entire XML content of source file body.
   *
   * @param typeName
   * @returns
   */
  public async resolveSingleton<K extends keyof typeof SingletonRegistry>(
    typeName: K
  ): Promise<SingletonReturnTypes[K]> {
    const retriever = SingletonRegistry[typeName];
    const { toRetrieve, cached } = this.fetchCached([typeName]);
    if (toRetrieve.length > 0) {
      const retrieveResults = await retriever.resolve(this.connection);
      this.cache.set(typeName, retrieveResults);
      return retrieveResults as SingletonReturnTypes[K];
    }
    return cached[typeName] as SingletonReturnTypes[K];
  }

  private cacheResults(results: Record<string, Metadata>): void {
    Object.entries(results).forEach(([cname, mdata]) => {
      this.cache.set(cname, mdata);
    });
  }

  private fetchCached(componentNames: string[]): { toRetrieve: string[]; cached: Record<string, Metadata> } {
    const toRetrieve = [];
    const cached: Record<string, Metadata> = {};
    for (const cname of componentNames) {
      if (this.cache.isCached(cname)) {
        cached[cname] = this.cache.fetch(cname);
      } else {
        toRetrieve.push(cname);
      }
    }
    return { toRetrieve, cached };
  }
}

class MetadataCache {
  private components: Record<string, Metadata> = {};

  public isCached(cmpName: string): boolean {
    return this.components[cmpName] !== undefined && this.components[cmpName] !== null;
  }

  public fetch(cmpName: string): Metadata {
    if (!this.isCached(cmpName)) {
      throw new Error('Component not cached. Check first before fetching: ' + cmpName);
    }
    return this.components[cmpName];
  }

  public set(cmpName: string, content: Metadata): void {
    this.components[cmpName] = content;
  }
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
  Profile: new NamedMetadataQueryable<ProfileXml, 'Profile'>({
    objectName: 'Profile',
    nameField: 'Name',
    parsePostProcessor: (parseResult): ProfileMetadata => ({
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
    retrieveName: 'ConnectedApp',
    retrieveType: 'Settings',
  }),
};

type NamedReturnTypes = {
  [K in keyof typeof NamedTypesRegistry]: Awaited<ReturnType<(typeof NamedTypesRegistry)[K]['resolve']>>;
};

type SingletonReturnTypes = {
  [K in keyof typeof SingletonRegistry]: Awaited<ReturnType<(typeof SingletonRegistry)[K]['resolve']>>;
};

type ProfileXml = {
  Profile: ProfileMetadata;
};

type PermissionSetXml = {
  PermissionSet: PermissionSet;
};

type ConnectedAppSettingsXml = {
  ConnectedAppSettings: ConnectedAppSettings;
};
