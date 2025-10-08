import fs, { PathLike } from 'node:fs';
import path from 'node:path';
import { stubSfCommandUx } from '@salesforce/sf-plugins-core';
import { MockTestOrgData, TestContext } from '@salesforce/core/testSetup';
import { CUSTOM_PERMS_QUERY, PROFILES_QUERY } from '../../src/libs/policies/policies.js';
import SfConnectionMocks from './sfConnectionMocks.js';

const DEFAULT_MOCKS = {
  describes: {
    PermissionSet: 'test/mocks/data/describeResults/PermissionSet.json',
  },
  queries: {} as Record<string, string>,
};

export default class AuditTestContext {
  public context = new TestContext();
  public targetOrg = new MockTestOrgData();
  public outputDirectory: PathLike;
  public defaultPath = path.join('my-test-org');
  public sfCommandStubs: ReturnType<typeof stubSfCommandUx>;
  public mocks: SfConnectionMocks;

  public constructor(dirPath?: string) {
    if (dirPath) {
      this.outputDirectory = path.join(dirPath);
    } else {
      this.outputDirectory = this.defaultPath;
    }
    this.mocks = new SfConnectionMocks(buildDefaultMocks());
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
    this.mocks = new SfConnectionMocks(buildDefaultMocks());
  }
}

function buildDefaultMocks() {
  const defaults = structuredClone(DEFAULT_MOCKS);
  defaults.queries[CUSTOM_PERMS_QUERY] = 'test/mocks/data/queryResults/customPermissions.json';
  defaults.queries[PROFILES_QUERY] = 'test/mocks/data/queryResults/profiles.json';
  return defaults;
}
