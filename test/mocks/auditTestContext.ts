import fs, { PathLike } from 'node:fs';
import path from 'node:path';
import { PermissionSet } from '@jsforce/jsforce-node/lib/api/metadata.js';
import { stubSfCommandUx } from '@salesforce/sf-plugins-core';
import { MockTestOrgData, TestContext } from '@salesforce/core/testSetup';
import MdapiRetriever, { parseAsPermissionset } from '../../src/libs/mdapiRetriever.js';
import { CUSTOM_PERMS_QUERY, PERMISSION_SETS_QUERY, PROFILES_QUERY } from '../../src/libs/config/queries.js';
import SfConnectionMocks from './sfConnectionMocks.js';

const DEFAULT_MOCKS = {
  describes: {
    PermissionSet: 'test/mocks/data/describeResults/PermissionSet.json',
  },
  queries: {} as Record<string, string>,
};

export default class AuditTestContext {
  public context: TestContext;
  public targetOrg: MockTestOrgData;
  public outputDirectory: PathLike;
  public defaultPath = path.join('my-test-org');
  public sfCommandStubs!: ReturnType<typeof stubSfCommandUx>;
  public mocks: SfConnectionMocks;

  public constructor(dirPath?: string) {
    this.context = new TestContext();
    this.targetOrg = new MockTestOrgData();
    this.targetOrg.instanceUrl = 'https://test-org.my.salesforce.com';
    if (dirPath) {
      this.outputDirectory = path.join(dirPath);
    } else {
      this.outputDirectory = this.defaultPath;
    }
    this.mocks = new SfConnectionMocks(buildDefaultMocks());
  }

  public async init() {
    await this.context.stubAuths(this.targetOrg);
    this.sfCommandStubs = stubSfCommandUx(this.context.SANDBOX);
    fs.mkdirSync(this.outputDirectory, { recursive: true });
    this.context.fakeConnectionRequest = this.mocks.fakeConnectionRequest;
    this.context.SANDBOX.stub(MdapiRetriever.prototype, 'retrievePermissionsets').callsFake(retrievePermsetsStub);
  }

  public reset() {
    this.context.restore();
    process.removeAllListeners();
    fs.rmSync(this.outputDirectory, { force: true, recursive: true });
    fs.rmSync(this.defaultPath, { force: true, recursive: true });
    this.mocks = new SfConnectionMocks(buildDefaultMocks());
  }
}

export function clearAuditReports(workingDir: string): void {
  fs.readdirSync(workingDir)
    .filter((fn) => fn.match(/(report_).*\.json$/) !== null)
    .forEach((reportFile) => fs.rmSync(path.join(workingDir, reportFile)));
}

async function retrievePermsetsStub(cmpNames: string[]): Promise<Record<string, PermissionSet>> {
  const result: Record<string, PermissionSet> = {};
  cmpNames.forEach((cname) => {
    result[cname] = parseAsPermissionset(
      path.join('test', 'mocks', 'data', 'retrieves', 'full-permsets', `${cname}.permissionset-meta.xml`)
    );
  });
  return result;
}

function buildDefaultMocks() {
  const defaults = structuredClone(DEFAULT_MOCKS);
  defaults.queries[CUSTOM_PERMS_QUERY] = 'test/mocks/data/queryResults/customPermissions.json';
  defaults.queries[PROFILES_QUERY] = 'test/mocks/data/queryResults/profiles.json';
  defaults.queries[PERMISSION_SETS_QUERY] = 'test/mocks/data/queryResults/empty.json';
  defaults.queries["SELECT Name,Metadata FROM Profile WHERE Name = 'System Administrator'"] =
    'test/mocks/data/queryResults/admin-profile-with-metadata.json';
  defaults.queries["SELECT Name,Metadata FROM Profile WHERE Name = 'Standard User'"] =
    'test/mocks/data/queryResults/standard-profile-with-metadata.json';
  return defaults;
}
