import fs, { PathLike } from 'node:fs';
import path from 'node:path';
import { Connection } from '@salesforce/core';
import { SinonSandbox } from 'sinon';
import { XMLParser } from 'fast-xml-parser';
import { stubSfCommandUx } from '@salesforce/sf-plugins-core';
import { copyDir } from '@salesforce/packaging/lib/utils/packageUtils.js';
import { ComponentSet, MetadataApiRetrieve, RequestStatus, RetrieveResult } from '@salesforce/source-deploy-retrieve';
import { MockTestOrgData, TestContext } from '@salesforce/core/testSetup';
import {
  AuditRunConfig,
  PermissionSetConfig,
  PermissionSetsMap,
  ProfilesMap,
  UserConfig,
} from '../../src/libs/core/file-mgmt/schema.js';
import { PartialPolicyRuleResult } from '../../src/libs/core/registries/types.js';
import {
  CONNECTED_APPS_QUERY,
  CUSTOM_PERMS_QUERY,
  OAUTH_TOKEN_QUERY,
  PERMISSION_SETS_QUERY,
  RETRIEVE_CACHE,
} from '../../src/libs/core/constants.js';
import {
  PolicyRuleViolation,
  PolicyRuleViolationMute,
  RuleComponentMessage,
} from '../../src/libs/core/result-types.js';
import AuditRunMultiStageOutput from '../../src/ux/auditRunMultiStage.js';
import { MDAPI } from '../../src/salesforce/index.js';
import SfConnectionMocks from './sfConnectionMocks.js';

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
    this.mocks = createConnectionMocks();
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
    fs.rmSync(RETRIEVE_CACHE, { force: true, recursive: true });
    this.mocks = createConnectionMocks();
    this.mockAuditConfig = { policies: {}, classifications: {} };
    MDAPI.clearCache();
  }

  public stubMetadataRetrieve(dirPath: string) {
    const fullyResolvedPath = path.join(SRC_MOCKS_BASE_PATH, dirPath);
    if (this.retrieveStub) {
      this.retrieveStub.restore();
    }
    this.retrieveStub = this.context.SANDBOX.stub(ComponentSet.prototype, 'retrieve').callsFake((opts) => {
      // this behavior mimicks the original behavior of metadata retrieve as closely as possible
      // each retrieve creates a temporary dictionary that contains all files
      const retrievePath = path.join(opts.output, `metadataPackage_${Date.now()}`);
      fs.mkdirSync(retrievePath, { recursive: true });
      copyDir(fullyResolvedPath, retrievePath);
      return Promise.resolve(new MetadataApiRetrieveMock(retrievePath) as unknown as MetadataApiRetrieve);
    });
    return this.retrieveStub;
  }

  /**
   * Replaces the entire profiles classification
   *
   * @param classifications
   */
  public mockProfileClassifications(classifications: ProfilesMap): void {
    this.mockAuditConfig.classifications.profiles = undefined;
    Object.entries(classifications).forEach(([profileName, classification]) => {
      this.mockProfileClassification(profileName, classification);
    });
  }

  /**
   * Replaces the entire permission sets classification
   *
   * @param classifications
   */
  public mockPermSetClassifications(classifications: PermissionSetsMap): void {
    this.mockAuditConfig.classifications.permissionSets = undefined;
    Object.entries(classifications).forEach(([permSetName, classification]) => {
      this.mockPermSetClassification(permSetName, classification);
    });
  }

  /**
   * Mocks classification of a specific profile
   *
   * @param profileName
   * @param classification
   */
  public mockProfileClassification(profileName: string, classification: PermissionSetConfig): void {
    this.mockAuditConfig.classifications.profiles ??= { content: { profiles: {} } };
    this.mockAuditConfig.classifications.profiles.content.profiles[profileName] = classification;
  }

  /**
   * Mocks classification of a specific permission set
   *
   * @param permSetName
   * @param classification
   */
  public mockPermSetClassification(permSetName: string, classification: PermissionSetConfig): void {
    this.mockAuditConfig.classifications.permissionSets ??= { content: { permissionSets: {} } };
    this.mockAuditConfig.classifications.permissionSets.content.permissionSets[permSetName] = classification;
  }

  public mockUserClassification(username: string, classification: UserConfig): void {
    this.mockAuditConfig.classifications.users ??= { content: { users: {} } };
    this.mockAuditConfig.classifications.users.content.users[username] = classification;
  }
}

class MetadataApiRetrieveMock {
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

export function parseXmlFile<T>(...filePath: string[]): T {
  const fileContent = fs.readFileSync(path.join(MOCK_DATA_BASE_PATH, ...filePath), 'utf-8');
  return new XMLParser().parse(fileContent) as T;
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

/**
 * Build path to test configs in test/mocks/data/audit-configs
 *
 * @param dirName
 * @returns
 */
export function buildAuditConfigPath(dirName: string): string {
  return path.join(MOCK_DATA_BASE_PATH, 'audit-configs', dirName);
}

function createConnectionMocks(): SfConnectionMocks {
  const defaults = {
    describes: {
      PermissionSet: 'test/mocks/data/describeResults/PermissionSet.json',
    },
    queries: {} as Record<string, string>,
  };
  defaults.queries[CUSTOM_PERMS_QUERY] = 'custom-permissions';
  defaults.queries[PERMISSION_SETS_QUERY] = 'empty';
  defaults.queries[CONNECTED_APPS_QUERY] = 'empty';
  defaults.queries[OAUTH_TOKEN_QUERY] = 'empty';
  const mocks = new SfConnectionMocks(defaults);
  mocks.mockUsers('active-user-details');
  mocks.mockProfiles('profiles');
  mocks.mockProfiles('profiles', ['System Administrator', 'Standard User', 'Custom Profile']);
  mocks.mockProfiles('admin-and-standard-profiles', ['System Administrator', 'Standard User']);
  mocks.mockProfileResolve('System Administrator', 'admin-profile-with-metadata');
  mocks.mockProfileResolve('Standard User', 'standard-profile-with-metadata');
  mocks.mockProfileResolve('Guest User Profile', 'empty');
  mocks.mockProfileResolve('Custom Profile', 'empty');
  mocks.mockLoginHistory('empty');
  // 14 days is option config in "full-valid" user policy
  mocks.mockLoginHistory('empty', 14);
  return mocks;
}

export function buildResultsPath(fileName: string): string {
  return path.join(QUERY_RESULTS_BASE, `${fileName}.json`);
}
