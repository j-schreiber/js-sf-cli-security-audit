import fs, { PathLike } from 'node:fs';
import path from 'node:path';
import { stubSfCommandUx } from '@salesforce/sf-plugins-core';
import { MockTestOrgData, TestContext } from '@salesforce/core/testSetup';
import SfConnectionMocks from './sfConnectionMocks.js';

const DEFAULT_MOCKS = {
  describes: {
    PermissionSet: 'test/mocks/data/describeResults/PermissionSet.json',
  },
  queries: {
    'SELECT Id,MasterLabel,DeveloperName FROM CustomPermission': 'test/mocks/data/queryResults/customPermissions.json',
  },
};
export default class AuditTestContext {
  public context = new TestContext();
  public targetOrg = new MockTestOrgData();
  public outputDirectory: PathLike;
  public defaultPath = path.join('policies');
  public sfCommandStubs: ReturnType<typeof stubSfCommandUx>;
  public mocks: SfConnectionMocks;

  public constructor(dirPath?: string) {
    if (dirPath) {
      this.outputDirectory = path.join(dirPath);
    } else {
      this.outputDirectory = path.join('tmp', 'tests', '12345');
    }
    this.mocks = new SfConnectionMocks(DEFAULT_MOCKS);
    this.sfCommandStubs = stubSfCommandUx(this.context.SANDBOX);
  }

  public init() {
    fs.mkdirSync(this.outputDirectory, { recursive: true });
    this.context.fakeConnectionRequest = this.mocks.fakeConnectionRequest;
  }

  public reset() {
    this.context.restore();
    process.removeAllListeners();
    this.sfCommandStubs = stubSfCommandUx(this.context.SANDBOX);
    fs.rmSync(this.outputDirectory, { force: true, recursive: true });
    fs.rmSync(this.defaultPath, { force: true, recursive: true });
    this.mocks = new SfConnectionMocks(DEFAULT_MOCKS);
  }
}
