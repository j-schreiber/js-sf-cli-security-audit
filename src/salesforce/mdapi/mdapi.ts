import { Connection } from '@salesforce/core';
import { Metadata } from '@jsforce/jsforce-node/lib/api/metadata.js';
import { MdapiRegistry, Registry } from './metadataRegistry.js';

export default class MDAPI {
  private static readonly retrievers = new Map<string, MDAPI>();
  private readonly cache: MetadataCache;

  public constructor(private readonly connection: Connection, private readonly registry: MdapiRegistry = Registry) {
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
  public async resolve<K extends keyof MdapiRegistry['namedTypes']>(
    typeName: K,
    componentNames: string[]
  ): Promise<NamedReturnTypes[K]> {
    const retriever = this.registry.namedTypes[typeName];
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
  public async resolveSingleton<K extends keyof MdapiRegistry['singletonTypes']>(
    typeName: K
  ): Promise<SingletonReturnTypes[K]> {
    const retriever = this.registry.singletonTypes[typeName];
    const { toRetrieve, cached } = this.fetchCached([typeName]);
    if (toRetrieve.length > 0) {
      const retrieveResults = await retriever.resolve(this.connection);
      this.cache.set(typeName, retrieveResults);
      return retrieveResults as SingletonReturnTypes[K];
    }
    return cached[typeName] as SingletonReturnTypes[K];
  }

  private cacheResults(results: Record<string, Metadata>): void {
    for (const [cname, mdata] of Object.entries(results)) {
      this.cache.set(cname, mdata);
    }
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

type NamedReturnTypes = {
  [K in keyof MdapiRegistry['namedTypes']]: Awaited<ReturnType<MdapiRegistry['namedTypes'][K]['resolve']>>;
};

type SingletonReturnTypes = {
  [K in keyof MdapiRegistry['singletonTypes']]: Awaited<ReturnType<MdapiRegistry['singletonTypes'][K]['resolve']>>;
};
