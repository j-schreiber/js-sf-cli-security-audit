import fs, { PathLike } from 'node:fs';
import path from 'node:path';
import { stubSfCommandUx } from '@salesforce/sf-plugins-core';
import { MockTestOrgData, TestContext } from '@salesforce/core/testSetup';
import { DescribeSObjectResult } from '@jsforce/jsforce-node';
import { AnyJson, isString } from '@salesforce/ts-types';

export default class AuditTestContext {
  public context = new TestContext();
  public targetOrg = new MockTestOrgData();
  public outputDirectory: PathLike;
  public defaultPath = path.join('policies');
  public sfCommandStubs: ReturnType<typeof stubSfCommandUx>;

  /** A key/value map of mocked describe results. Use sobject developer name for keys */
  public describes: Record<string, Partial<DescribeSObjectResult>> = {};

  public constructor(dirPath?: string) {
    if (dirPath) {
      this.outputDirectory = path.join(dirPath);
    } else {
      this.outputDirectory = path.join('tmp', 'tests', '12345');
    }
    this.sfCommandStubs = stubSfCommandUx(this.context.SANDBOX);
  }

  public init() {
    this.describes['PermissionSet'] = loadDescribeResult('test/mocks/data/describeResults/PermissionSet.json');
    fs.mkdirSync(this.outputDirectory, { recursive: true });
    this.context.fakeConnectionRequest = this.mockQueryResults;
  }

  public reset() {
    process.removeAllListeners();
    fs.rmSync(this.outputDirectory, { force: true, recursive: true });
    fs.rmSync(this.defaultPath, { force: true, recursive: true });
  }

  public readonly mockQueryResults = (request: AnyJson): Promise<AnyJson> => {
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
    return Promise.reject(new Error(`No mock was defined for: ${JSON.stringify(request)}`));
  };
}

function loadDescribeResult(filePath: PathLike): DescribeSObjectResult {
  const content = fs.readFileSync(filePath, 'utf-8');
  return JSON.parse(content) as DescribeSObjectResult;
}
