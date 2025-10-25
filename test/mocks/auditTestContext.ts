import fs, { PathLike } from 'node:fs';
import path from 'node:path';
import { Connection } from '@salesforce/core';
import { SinonSandbox } from 'sinon';
import { ConnectedAppSettings, PermissionSet } from '@jsforce/jsforce-node/lib/api/metadata.js';
import { stubSfCommandUx } from '@salesforce/sf-plugins-core';
import { MockTestOrgData, TestContext } from '@salesforce/core/testSetup';
import MdapiRetriever, {
  parseAsConnectedAppSetting,
  parseAsPermissionset,
} from '../../src/libs/core/mdapi/mdapiRetriever.js';
import { AuditRunConfig } from '../../src/libs/core/file-mgmt/schema.js';
import { PartialPolicyRuleResult } from '../../src/libs/core/registries/types.js';
import {
  CONNECTED_APPS_QUERY,
  CUSTOM_PERMS_QUERY,
  OAUTH_TOKEN_QUERY,
  PERMISSION_SETS_QUERY,
  PROFILES_QUERY,
} from '../../src/libs/config/queries.js';
import {
  PolicyRuleViolation,
  PolicyRuleViolationMute,
  RuleComponentMessage,
} from '../../src/libs/core/result-types.js';
import AuditRunMultiStageOutput from '../../src/ux/auditRunMultiStage.js';
import SfConnectionMocks from './sfConnectionMocks.js';

const DEFAULT_MOCKS = {
  describes: {
    PermissionSet: 'test/mocks/data/describeResults/PermissionSet.json',
  },
  queries: {} as Record<string, string>,
};

export const MOCK_DATA_BASE_PATH = path.join('test', 'mocks', 'data');
export const QUERY_RESULTS_BASE = path.join(MOCK_DATA_BASE_PATH, 'queryResults');
export const RETRIEVES_BASE = path.join(MOCK_DATA_BASE_PATH, 'retrieves');

export default class AuditTestContext {
  public context: TestContext;
  public targetOrg: MockTestOrgData;
  public targetOrgConnection!: Connection;
  public outputDirectory: PathLike;
  public defaultPath = path.join('my-test-org');
  public sfCommandStubs!: ReturnType<typeof stubSfCommandUx>;
  public multiStageStub!: ReturnType<typeof stubMultiStageUx>;
  public mocks: SfConnectionMocks;
  public mockAppSetting: string;
  public mockPermSets: string;
  public mockAuditConfig: AuditRunConfig = { policies: {}, classifications: {} };

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
    this.mockAppSetting = path.join(
      RETRIEVES_BASE,
      'connected-app-settings',
      'api-security-controls-available-enabled.xml'
    );
    this.mockPermSets = path.join(RETRIEVES_BASE, 'full-permsets');
  }

  public async init() {
    await this.context.stubAuths(this.targetOrg);
    this.targetOrgConnection = await this.targetOrg.getConnection();
    this.sfCommandStubs = stubSfCommandUx(this.context.SANDBOX);
    this.multiStageStub = stubMultiStageUx(this.context.SANDBOX);
    fs.mkdirSync(this.outputDirectory, { recursive: true });
    this.context.fakeConnectionRequest = this.mocks.fakeConnectionRequest;
    this.context.SANDBOX.stub(MdapiRetriever.prototype, 'retrievePermissionsets').callsFake(this.retrievePermsetsStub);
    this.context.SANDBOX.stub(MdapiRetriever.prototype, 'retrieveConnectedAppSetting').callsFake(
      this.retrieveConnectedAppSettingStub
    );
  }

  public reset() {
    this.context.restore();
    process.removeAllListeners();
    fs.rmSync(this.outputDirectory, { force: true, recursive: true });
    fs.rmSync(this.defaultPath, { force: true, recursive: true });
    this.mocks = new SfConnectionMocks(buildDefaultMocks());
  }

  private retrieveConnectedAppSettingStub = (): Promise<ConnectedAppSettings> =>
    Promise.resolve(parseAsConnectedAppSetting(this.mockAppSetting));

  private retrievePermsetsStub = (cmpNames: string[]): Promise<Record<string, PermissionSet>> => {
    const result: Record<string, PermissionSet> = {};
    cmpNames.forEach((cname) => {
      const permsetFullPath = path.join(this.mockPermSets, `${cname}.permissionset-meta.xml`);
      if (fs.existsSync(permsetFullPath)) {
        result[cname] = parseAsPermissionset(permsetFullPath);
      }
    });
    return Promise.resolve(result);
  };
}

export function newRuleResult(ruleName?: string): PartialPolicyRuleResult {
  return {
    ruleName: ruleName ?? 'Mock_Rule',
    violations: new Array<PolicyRuleViolation>(),
    mutedViolations: new Array<PolicyRuleViolationMute>(),
    warnings: new Array<RuleComponentMessage>(),
    errors: [],
  };
}

export function parseFileAsJson<T>(...filePath: string[]): T {
  const fileContent = fs.readFileSync(path.join(MOCK_DATA_BASE_PATH, ...filePath), 'utf-8');
  return JSON.parse(fileContent) as T;
}

export function clearAuditReports(workingDir: string): void {
  fs.readdirSync(workingDir)
    .filter((fn) => fn.match(/(report_).*\.json$/) !== null)
    .forEach((reportFile) => fs.rmSync(path.join(workingDir, reportFile)));
}

export function stubMultiStageUx(sandbox: SinonSandbox): AuditRunMultiStageOutput {
  const multiStageStub = sandbox.createStubInstance(AuditRunMultiStageOutput);
  sandbox.stub(AuditRunMultiStageOutput, 'create').returns(multiStageStub);
  return multiStageStub;
}

function buildDefaultMocks() {
  const defaults = structuredClone(DEFAULT_MOCKS);
  defaults.queries[CUSTOM_PERMS_QUERY] = buildResultsPath('custom-permissions');
  defaults.queries[PROFILES_QUERY] = buildResultsPath('profiles');
  defaults.queries[PERMISSION_SETS_QUERY] = buildResultsPath('empty');
  defaults.queries[CONNECTED_APPS_QUERY] = buildResultsPath('empty');
  defaults.queries[OAUTH_TOKEN_QUERY] = buildResultsPath('empty');
  defaults.queries[buildProfilesQuery('System Administrator')] = buildResultsPath('admin-profile-with-metadata');
  defaults.queries[buildProfilesQuery('Standard User')] = buildResultsPath('standard-profile-with-metadata');
  defaults.queries[buildProfilesQuery('Custom Profile')] = buildResultsPath('empty');
  return defaults;
}

function buildProfilesQuery(profileName: string): string {
  return `SELECT Name,Metadata FROM Profile WHERE Name = '${profileName}'`;
}

export function buildResultsPath(fileName: string): string {
  return path.join(QUERY_RESULTS_BASE, `${fileName}.json`);
}
