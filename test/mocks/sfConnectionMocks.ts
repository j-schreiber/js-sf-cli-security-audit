import fs, { PathLike } from 'node:fs';
import path from 'node:path';
import { DescribeSObjectResult, Record as JsForceRecord } from '@jsforce/jsforce-node';
import { AnyJson, isString } from '@salesforce/ts-types';

export type SfConnectionMockConfig = {
  describes?: Record<string, PathLike>;
  queries?: Record<string, string>;
};

export const QUERY_RESULTS_BASE = path.join('test', 'mocks', 'data', 'queryResults');

export default class SfConnectionMocks {
  public describes: Record<string, Partial<DescribeSObjectResult>>;
  public queries: Record<string, JsForceRecord[]>;

  public constructor(config: SfConnectionMockConfig) {
    this.describes = {};
    this.queries = {};
    if (config.describes) {
      Object.entries(config.describes).forEach(([sobjectName, describePath]) => {
        this.setDescribeMock(sobjectName, describePath);
      });
    }
    if (config.queries) {
      Object.entries(config.queries).forEach(([queryString, resultsPath]) => {
        this.setQueryMock(queryString, resultsPath);
      });
    }
  }

  /**
   * Mock query results from a file. The file must be located in queryResults
   * standard mock folder.
   *
   * @param queryString
   * @param fileName file name without '.json' suffix
   */
  public setQueryMock(queryString: string, fileName: string): void {
    const fullPath = path.join(QUERY_RESULTS_BASE, `${fileName}.json`);
    this.queries[queryString] = loadRecords(fullPath);
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
   * Assign this method by reference (without "()") to the `TestContext`
   * "fakeConnectionRequest" method.
   *
   * @param request
   */
  public readonly fakeConnectionRequest = (request: AnyJson): Promise<AnyJson> => {
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
      if (this.queries[queryParam] === undefined) {
        return Promise.reject({
          data: { errorCode: 'UNKNOWN_QUERY', message: `A query was executed that was not mocked: ${queryParam}` },
        });
      }
      const records = this.queries[queryParam];
      return Promise.resolve({ done: true, totalSize: records.length, records } as AnyJson);
    }
    return Promise.reject(new Error(`No mock was defined for: ${JSON.stringify(request)}`));
  };
}

function extractDecodedQueryParam(url: string) {
  if (url.includes('?q=')) {
    return decodeURIComponent(url.split('q=')[1]);
  } else {
    return '';
  }
}

export function loadDescribeResult(filePath: PathLike): DescribeSObjectResult {
  const content = fs.readFileSync(filePath, 'utf-8');
  return JSON.parse(content) as DescribeSObjectResult;
}

export function loadRecords(filePath: PathLike): JsForceRecord[] {
  const content = fs.readFileSync(filePath, 'utf-8');
  return JSON.parse(content) as JsForceRecord[];
}
