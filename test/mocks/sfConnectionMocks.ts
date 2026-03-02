import fs, { PathLike } from 'node:fs';
import path from 'node:path';
import { DescribeSObjectResult, Record as JsForceRecord, QueryResult } from '@jsforce/jsforce-node';
import { AnyJson, isString } from '@salesforce/ts-types';
import { TestContext } from '@salesforce/core/testSetup';
import { ComponentSet, MetadataApiRetrieve, RequestStatus, RetrieveResult } from '@salesforce/source-deploy-retrieve';
import { copyDir } from '@salesforce/packaging/lib/utils/packageUtils.js';
import {
  buildLoginHistoryQuery,
  buildPermsetAssignmentsQuery,
  ACTIVE_USERS_DETAILS_QUERY,
  ALL_USERS_DETAILS_QUERY,
} from '../../src/salesforce/repositories/users/queries.js';
import { CUSTOM_PERMS_QUERY } from '../../src/salesforce/describes/orgDescribe.types.js';
import { buildProfilesQuery } from '../../src/salesforce/repositories/profiles/queries.js';
import { PERMISSION_SETS_QUERY } from '../../src/salesforce/repositories/perm-sets/queries.js';
import {
  ALL_EXISTING_USER_IDS,
  CONNECTED_APPS_QUERY,
  COUNT_TOKEN_QUERY,
  formatCountSoql,
  formatTokenSoql,
  OAUTH_TOKEN_QUERY,
} from '../../src/salesforce/repositories/connected-apps/queries.js';
import { SfMinimalUser, SfOauthToken } from '../../src/salesforce/repositories/connected-apps/connected-app.types.js';
import { MOCK_DATA_BASE_PATH, SRC_MOCKS_BASE_PATH, QUERY_RESULTS_BASE, FULL_QUERY_RESULTS_BASE } from './data/paths.js';

export type SfConnectionMockConfig = {
  describes?: Record<string, PathLike>;
  queries?: Record<string, string>;
};
export default class SfConnectionMocks {
  public describes: Record<string, Partial<DescribeSObjectResult>>;
  public queries: Record<string, JsForceRecord[]>;
  public retrieveStub?: sinon.SinonStub;
  public fullQueryResults: Record<string, AnyJson>;

  public constructor(private readonly context: TestContext) {
    this.describes = {};
    this.queries = {};
    this.fullQueryResults = {};
    this.context.fakeConnectionRequest = this.fakeConnectionRequest;
  }

  /**
   * Prepares mock results for describe and query calls
   *
   * @param config
   */
  public prepareMocks(config: SfConnectionMockConfig) {
    this.describes = {};
    this.queries = {};
    if (config.describes) {
      for (const [sobjectName, describePath] of Object.entries(config.describes)) {
        this.setDescribeMock(sobjectName, describePath);
      }
    }
    if (config.queries) {
      for (const [queryString, resultsPath] of Object.entries(config.queries)) {
        this.setQueryMock(queryString, resultsPath);
      }
    }
  }

  public restoreStubs() {
    this.context.fakeConnectionRequest = this.fakeConnectionRequest;
  }

  /**
   * Mock query results from a file. The file must be located in query-result-records
   * standard mock folder.
   *
   * @param queryString
   * @param fileName file name without '.json' suffix
   */
  public setQueryMock(
    queryString: string,
    fileName: string,
    transformer?: (a: JsForceRecord) => JsForceRecord
  ): JsForceRecord[] {
    const fullPath = path.join(QUERY_RESULTS_BASE, `${fileName}.json`);
    const records = loadRecords(fullPath);
    if (transformer) {
      this.queries[queryString] = records.map(transformer);
    } else {
      this.queries[queryString] = records;
    }
    return records;
  }

  /**
   * Mocks a full query result for a SOQL or a query pointer. File must be located in query-results
   * standard mock folder. Any full result overrides query mocks.
   *
   * @param soqlOrQueryLocator
   * @param fileName
   */
  public setFullQueryResult(soqlOrQueryLocator: string, fileName: string): QueryResult<JsForceRecord> {
    const fullPath = path.join(FULL_QUERY_RESULTS_BASE, `${fileName}.json`);
    const content = fs.readFileSync(fullPath, 'utf-8');
    const result = JSON.parse(content) as QueryResult<JsForceRecord>;
    this.fullQueryResults[soqlOrQueryLocator] = result;
    return result;
  }

  /**
   * Overrides the default describe mocks for a given sobject type
   *
   * @param sobjectName
   * @param resultPath
   */
  public setDescribeMock(sobjectName: string, resultPath: PathLike): void {
    this.describes[sobjectName] = loadDescribeResult(resultPath);
  }

  /**
   * Mocks a "metadata SOQL" to resolve profile metadata.
   *
   * @param profileName
   * @param resultFile
   */
  public mockProfileResolve(profileName: string, resultFile: string): void {
    const filePath = path.join(MOCK_DATA_BASE_PATH, 'profiles-metadata', `${resultFile}.json`);
    const records = loadRecords(filePath);
    this.queries[`SELECT Name,Metadata FROM Profile WHERE Name = '${profileName}'`] = records;
  }

  /**
   * Mock login history queries
   *
   * @param resultFile
   * @param daysToAnalyse
   */
  public mockLoginHistory(resultFile: string, daysToAnalyse?: number): void {
    this.setQueryMock(buildLoginHistoryQuery(daysToAnalyse), resultFile);
  }

  /**
   * Mocks an unconstrainted profiles query (all profiles) or queries
   * that include specific profiles.
   *
   * @param resultFile
   * @param profileNames
   */
  public mockProfiles(resultFile: string, profileNames?: string[]): void {
    this.setQueryMock(buildProfilesQuery(profileNames), resultFile);
  }

  /**
   * Results for (standard) users query
   *
   * @param resultFile
   * @param activeOnly Only include active users
   */
  public mockUsers(
    resultFile: string,
    transformer?: (a: JsForceRecord) => JsForceRecord,
    activeOnly: boolean = true
  ): void {
    // reset both queries to avoid unexpected results
    delete this.queries[ACTIVE_USERS_DETAILS_QUERY];
    delete this.queries[ALL_USERS_DETAILS_QUERY];
    // only initialise one query
    if (activeOnly) {
      this.setQueryMock(ACTIVE_USERS_DETAILS_QUERY, resultFile, transformer);
    } else {
      this.setQueryMock(ALL_USERS_DETAILS_QUERY, resultFile, transformer);
    }
  }

  /**
   * Results for permission set assignments. The actual assigneeIds are in the
   * results file - the method param only sets the mock for query id.
   *
   * @param resultFile
   * @param assigneeIds
   */
  public mockPermsetAssignments(resultFile: string, assigneeIds: string[]): void {
    this.setQueryMock(buildPermsetAssignmentsQuery(assigneeIds), resultFile);
  }

  public mockPermissionSets(resultFile: string): void {
    this.setQueryMock(PERMISSION_SETS_QUERY, resultFile);
  }

  public mockCustomPermissions(resultFile: string): void {
    this.setQueryMock(CUSTOM_PERMS_QUERY, resultFile);
  }

  public mockConnectedApps(resultFile: string): void {
    this.setQueryMock(CONNECTED_APPS_QUERY, resultFile);
  }

  public mockOAuthTokens(resultFile: string): void {
    const mockRecords = this.setQueryMock(OAUTH_TOKEN_QUERY, resultFile);
    this.fullQueryResults[COUNT_TOKEN_QUERY] = { done: true, records: [], totalSize: mockRecords.length };
  }

  public mockOAuthTokenRecords(records: SfOauthToken[]): void {
    this.queries[OAUTH_TOKEN_QUERY] = records;
    this.fullQueryResults[COUNT_TOKEN_QUERY] = { done: true, records: [], totalSize: records.length };
  }

  public mockFilteredTokenRecords(userIds: string[], records: SfOauthToken[]): void {
    const chunkQuery = formatTokenSoql(userIds);
    const chunkCountQuery = formatCountSoql(userIds);
    this.queries[chunkQuery] = records;
    this.fullQueryResults[chunkCountQuery] = { done: true, records: [], totalSize: records.length };
  }

  public mockUserRecords(records: SfMinimalUser[]): void {
    this.queries[ALL_EXISTING_USER_IDS] = records;
  }

  /**
   * Stub a component set metadata retrieve. `ComponentSet.retrieve` will return
   * all contents of the folder.
   *
   * @param folderName folder that exists in mocks/data/mdapi-retrieve-mocks
   * @returns
   */
  public async stubMetadataRetrieve(folderName: string) {
    const fullyResolvedPath = path.join(SRC_MOCKS_BASE_PATH, folderName);
    this.retrieveStub?.restore();
    this.retrieveStub = this.context.SANDBOX.stub(ComponentSet.prototype, 'retrieve').callsFake(async (opts) => {
      // this behavior mimicks the original behavior of metadata retrieve as closely as possible
      // each retrieve creates a temporary dictionary that contains all files
      const retrieveDirName = opts.zipFileName ? opts.zipFileName.split('.')[0] : `metadataPackage_${Date.now()}`;
      const retrievePath = path.join(opts.output, retrieveDirName);
      fs.mkdirSync(retrievePath, { recursive: true });
      copyDir(fullyResolvedPath, retrievePath);
      return Promise.resolve(new MetadataApiRetrieveMock(retrievePath) as unknown as MetadataApiRetrieve);
    });
    return this.retrieveStub;
  }

  //        PRIVATE ZONE

  /**
   * Assign this method by reference (without "()") to the `TestContext`
   * "fakeConnectionRequest" method.
   *
   * @param request
   */
  private readonly fakeConnectionRequest = (request: AnyJson): Promise<AnyJson> => {
    // all describe calls
    if (isString(request) && request.endsWith('/describe')) {
      const requestUrl = request.split('/');
      const sobjectName = requestUrl[requestUrl.length - 2];
      if (this.describes[sobjectName] === undefined) {
        // the actual error message, if sobject type is not found with little debugging info
        return Promise.reject({
          data: { errorCode: 'NOT_FOUND', message: `The requested resource ${sobjectName} does not exist` },
        });
      }
      return Promise.resolve(this.describes[sobjectName] as AnyJson);
    }
    // assume its a call to /query? now
    const url = (request as { url: string }).url;
    if (url.includes('/query?q=')) {
      const queryParam = extractDecodedQueryParam(url);
      // if we mocked a full query result, use this mock
      if (this.fullQueryResults[queryParam]) {
        return Promise.resolve(this.fullQueryResults[queryParam]);
      }
      if (this.queries[queryParam] === undefined) {
        return Promise.reject({
          data: { errorCode: 'UNKNOWN_QUERY', message: `A query was executed that was not mocked: ${queryParam}` },
        });
      }
      // return records and auto-generate result otherwise
      const records = this.queries[queryParam];
      return Promise.resolve({ done: true, totalSize: records.length, records } as AnyJson);
    }
    // check if its a call to a query pointer (object prefix is 0r8)
    if (url.includes('/query/0r8')) {
      const queryLocator = extractQueryLocator(url);
      if (this.fullQueryResults[queryLocator]) {
        return Promise.resolve(this.fullQueryResults[queryLocator]);
      }
    }
    return Promise.reject(new Error(`No mock was defined for: ${JSON.stringify(request)}`));
  };
}

export class MetadataApiRetrieveMock {
  public constructor(private readonly dirPath?: string) {}

  public async pollStatus(): Promise<RetrieveResult> {
    let cmpSet: ComponentSet;
    if (this.dirPath && this.dirPath !== '') {
      cmpSet = ComponentSet.fromSource(this.dirPath);
    } else {
      cmpSet = new ComponentSet();
    }
    return new RetrieveResult(
      { done: true, status: RequestStatus.Succeeded, success: true, fileProperties: [], id: '1', zipFile: '' },
      cmpSet
    );
  }
}

function extractDecodedQueryParam(url: string) {
  if (url.includes('?q=')) {
    return decodeURIComponent(url.split('q=')[1]);
  } else {
    return '';
  }
}

function extractQueryLocator(url: string) {
  const locatorStart = url.indexOf('/0r8') + 1;
  return url.slice(locatorStart);
}

function loadDescribeResult(filePath: PathLike): DescribeSObjectResult {
  const content = fs.readFileSync(filePath, 'utf-8');
  return JSON.parse(content) as DescribeSObjectResult;
}

function loadRecords(filePath: PathLike): JsForceRecord[] {
  const content = fs.readFileSync(filePath, 'utf-8');
  return JSON.parse(content) as JsForceRecord[];
}
