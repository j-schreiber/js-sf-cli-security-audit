import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { DescribeSObjectResult, QueryOptions, QueryResult, Record as JsForceRecord } from '@jsforce/jsforce-node';
import { FileProperties } from '@jsforce/jsforce-node/lib/api/metadata.js';
import { Connection, Logger, Messages } from '@salesforce/core';
import { ComponentSet, RetrieveResult } from '@salesforce/source-deploy-retrieve';
import { createDigest } from '../utils.js';
import { RETRIEVE_CACHE, TMP_DIR } from './mdapi/constants.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'salesforceConnectionErrors');

const DEV_MODE_WRITE_DIR = path.join(TMP_DIR, `${Date.now()}`);

/**
 * Wrapper around the default `Connection` from core to add
 * meaningful logging and error bubbling for better UX and debugging.
 */
export default class SfConnection {
  /**
   * Use this flag during local testing to write all
   * query results to .jsc tmp dir.
   */
  public static devMode: boolean = false;

  public constructor(public readonly coreConnection: Connection, private logger?: Logger) {}

  /**
   * Create new instance with default logger
   *
   * @param con
   * @returns
   */
  public static async create(con: Connection): Promise<SfConnection> {
    const logger = await Logger.child('jsc:sae');
    return new SfConnection(con, logger);
  }

  /**
   * Executes a query against standard query API or tooling API
   *
   * @param soql
   * @param isTooling
   * @returns
   */
  public async query<T extends JsForceRecord>(
    soql: string,
    isTooling: boolean = false,
    queryOptions?: Partial<QueryOptions>
  ): Promise<QueryResult<T>> {
    const logger = await this.getLogger();
    logger.debug(`Executing query ${isTooling ? '(Tooling)' : ''}: ${soql}`);
    const definitiveOpts = queryOptions ?? {
      autoFetch: true,
    };
    try {
      const result = isTooling
        ? await this.coreConnection.tooling.query<T>(soql, definitiveOpts)
        : await this.coreConnection.query<T>(soql, definitiveOpts);
      if (SfConnection.devMode) {
        writeFileSafe(path.join(DEV_MODE_WRITE_DIR, 'queries'), createDigest(soql, 16) + '.json', result);
      }
      return result;
    } catch (error) {
      logger.error(`Failed to execute query: ${soql}`);
      logger.error(error);
      // downstream logic in other modules depends on specific error codes
      // that cannot be passed to SfError. Therefore, the error is re-thrown
      if (isConnectionError(error) && error.errorCode === 'EXCEEDED_ID_LIMIT') {
        throw error;
      }
      const errMsg = isConnectionError(error) ? error.data.message : 'Unknown error';
      throw messages.createError('Query', [soql, errMsg], undefined, error as Error);
    }
  }

  /**
   * Describes an SObject and returns the describe result
   *
   * @param sobjectName
   * @returns
   */
  public async describe(sobjectName: string): Promise<DescribeSObjectResult> {
    const logger = await this.getLogger();
    logger.debug('Describing: ' + sobjectName);
    try {
      const result = await this.coreConnection.describe(sobjectName);
      if (SfConnection.devMode) {
        writeFileSafe(path.join(DEV_MODE_WRITE_DIR, 'describes'), `${sobjectName}.json`, result);
      }
      return result;
    } catch (error) {
      logger.error(`Failed to describe: ${sobjectName}`);
      logger.error(error);
      const details = isConnectionError(error) ? `${error.errorCode}: ${error.data.message}` : 'Unknown error';
      throw messages.createError('DescribeSObjectFail', [sobjectName, details]);
    }
  }

  /**
   * Retrieves a component set as metadata and polls until the retrieve
   * result is ready.
   *
   * @param components
   * @param packageName
   * @returns
   */
  public async retrieve(components: ComponentSet, packageName: string): Promise<RetrieveResult> {
    const logger = await this.getLogger();
    logger.debug('Starting metadata retrieve: ' + formatComponentSet(components));
    try {
      const retrieveRequest = await components.retrieve({
        usernameOrConnection: this.coreConnection,
        format: 'metadata',
        unzip: true,
        singlePackage: true,
        zipFileName: `${packageName}.zip`,
        output: RETRIEVE_CACHE,
      });
      const mdapiRetrieveResult = await retrieveRequest.pollStatus();
      logger.debug('Retrieve successful');
      return mdapiRetrieveResult;
    } catch (error) {
      logger.error('Failed to retrieve metadata');
      logger.error(error);
      const details = isConnectionError(error) ? error.data.message : 'Unknown error';
      throw messages.createError('MetadataRetrieve', [details]);
    }
  }

  /**
   * Lists available metadata of a specific type on the target org
   *
   * @param type
   * @returns
   */
  public async listMetadata(type: string): Promise<FileProperties[]> {
    const logger = await this.getLogger();
    logger.debug('List available metadata on org for: ' + type);
    const types = await this.coreConnection.metadata.list({ type });
    if (SfConnection.devMode) {
      writeFileSafe(path.join(DEV_MODE_WRITE_DIR, 'metadata-list'), `${type}.json`, types);
    }
    return types;
  }

  private async getLogger(): Promise<Logger> {
    if (!this.logger) {
      this.logger = await Logger.child('jsc:sae');
    }
    return this.logger;
  }
}

type ConnectionError = {
  errorCode: string;
  data: {
    message: string;
  };
};

export function isConnectionError(error: unknown): error is ConnectionError {
  return typeof error === 'object' && error != null && 'errorCode' in error && 'data' in error;
}

function formatComponentSet(cmpSet: ComponentSet): string {
  const types: Record<string, string[]> = {};
  for (const cmp of cmpSet.toArray()) {
    if (!types[cmp.type.name]) {
      types[cmp.type.name] = [];
    }
    types[cmp.type.name].push(cmp.fullName);
  }
  return Object.entries(types)
    .map(([typeName, cmps]) => `[${typeName}: ${cmps.join(',')}]`)
    .join('; ');
}

function writeFileSafe(filePath: string, fileName: string, data: unknown): void {
  mkdirSync(filePath, { recursive: true });
  writeFileSync(path.join(filePath, fileName), JSON.stringify(data, null, 2));
}
