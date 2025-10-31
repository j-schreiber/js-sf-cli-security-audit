import fs, { PathLike } from 'node:fs';
import path from 'node:path';
import { Connection } from '@salesforce/core';
import { SinonSandbox } from 'sinon';
import { stubSfCommandUx } from '@salesforce/sf-plugins-core';
import { ComponentSet, MetadataApiRetrieve, RequestStatus, RetrieveResult } from '@salesforce/source-deploy-retrieve';
import { MockTestOrgData, TestContext } from '@salesforce/core/testSetup';
import { AuditRunConfig } from '../../src/libs/core/file-mgmt/schema.js';
import { PartialPolicyRuleResult } from '../../src/libs/core/registries/types.js';
import {
  CONNECTED_APPS_QUERY,
  CUSTOM_PERMS_QUERY,
  OAUTH_TOKEN_QUERY,
  PERMISSION_SETS_QUERY,
  PROFILES_QUERY,
} from '../../src/libs/core/constants.js';
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
export const SRC_MOCKS_BASE_PATH = path.join(MOCK_DATA_BASE_PATH, 'mdapi-retrieve-mocks');

export default class AuditTestContext {
  public context: TestContext;
  public targetOrg: MockTestOrgData;
  public targetOrgConnection!: Connection;
  public outputDirectory: PathLike;
  public defaultPath = path.join('my-test-org');
  public sfCommandStubs!: ReturnType<typeof stubSfCommandUx>;
  public multiStageStub!: ReturnType<typeof stubMultiStageUx>;
  public mocks: SfConnectionMocks;
  public mockAuditConfig: AuditRunConfig = { policies: {}, classifications: {} };
  public retrieveStub?: sinon.SinonStub;

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
    this.targetOrgConnection = await this.targetOrg.getConnection();
    this.sfCommandStubs = stubSfCommandUx(this.context.SANDBOX);
    this.multiStageStub = stubMultiStageUx(this.context.SANDBOX);
    fs.mkdirSync(this.outputDirectory, { recursive: true });
    this.context.fakeConnectionRequest = this.mocks.fakeConnectionRequest;
    this.stubMetadataRetrieve('full');
  }

  public reset() {
    this.context.restore();
    process.removeAllListeners();
    fs.rmSync(this.outputDirectory, { force: true, recursive: true });
    fs.rmSync(this.defaultPath, { force: true, recursive: true });
    this.mocks = new SfConnectionMocks(buildDefaultMocks());
  }

  public stubMetadataRetrieve(dirPath: string) {
    const fullyResolvedPath = path.join(SRC_MOCKS_BASE_PATH, dirPath);
    if (this.retrieveStub) {
      this.retrieveStub.restore();
    }
    this.retrieveStub = this.context.SANDBOX.stub(ComponentSet.prototype, 'retrieve').resolves(
      new MetadataApiRetrieveMock(fullyResolvedPath) as unknown as MetadataApiRetrieve
    );
    return this.retrieveStub;
  }
}

class MetadataApiRetrieveMock {
  public constructor(private dirPath?: string) {}

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
  defaults.queries[CUSTOM_PERMS_QUERY] = 'custom-permissions';
  defaults.queries[PROFILES_QUERY] = 'profiles';
  defaults.queries[PERMISSION_SETS_QUERY] = 'empty';
  defaults.queries[CONNECTED_APPS_QUERY] = 'empty';
  defaults.queries[OAUTH_TOKEN_QUERY] = 'empty';
  defaults.queries[buildProfilesQuery('System Administrator')] = 'admin-profile-with-metadata';
  defaults.queries[buildProfilesQuery('Standard User')] = 'standard-profile-with-metadata';
  defaults.queries[buildProfilesQuery('Custom Profile')] = 'empty';
  return defaults;
}

function buildProfilesQuery(profileName: string): string {
  return `SELECT Name,Metadata FROM Profile WHERE Name = '${profileName}'`;
}

export function buildResultsPath(fileName: string): string {
  return path.join(QUERY_RESULTS_BASE, `${fileName}.json`);
}
