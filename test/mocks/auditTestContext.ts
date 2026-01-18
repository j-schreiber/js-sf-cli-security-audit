import fs, { PathLike } from 'node:fs';
import path from 'node:path';
import { Connection } from '@salesforce/core';
import { SinonSandbox } from 'sinon';
import { stubSfCommandUx } from '@salesforce/sf-plugins-core';
import { MockTestOrgData, TestContext } from '@salesforce/core/testSetup';
import { PartialPolicyRuleResult } from '../../src/libs/core/registries/types.js';
import {
  PolicyRuleViolation,
  PolicyRuleViolationMute,
  RuleComponentMessage,
} from '../../src/libs/audit-engine/registry/result.types.js';
import { AuditRunConfig } from '../../src/libs/audit-engine/index.js';
import {
  PermissionSetClassifications,
  ProfileClassifications,
  UserClassifications,
} from '../../src/libs/audit-engine/registry/shape/schema.js';
import AuditRunMultiStageOutput from '../../src/ux/auditRunMultiStage.js';
import { MDAPI } from '../../src/salesforce/index.js';
import { CUSTOM_PERMS_QUERY } from '../../src/libs/conf-init/permissionsClassification.js';
import { PERMISSION_SETS_QUERY } from '../../src/salesforce/repositories/perm-sets/queries.js';
import { CONNECTED_APPS_QUERY, OAUTH_TOKEN_QUERY } from '../../src/salesforce/repositories/connected-apps/queries.js';
import { RETRIEVE_CACHE } from '../../src/salesforce/mdapi/constants.js';
import SfConnectionMocks from './sfConnectionMocks.js';
import { MOCK_DATA_BASE_PATH } from './data/paths.js';

/**
 * A test context specifically designed for audit runs. Provides convenience function
 * to stub & assert command output & file operations, audit configs, and callouts to
 * Salesforce APIs (query, retrieve).
 */
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

  public constructor(dirPath?: string) {
    this.context = new TestContext();
    this.targetOrg = new MockTestOrgData();
    this.mocks = initDefaultMocks(new SfConnectionMocks(this.context));
    this.targetOrg.instanceUrl = 'https://test-org.my.salesforce.com';
    if (dirPath) {
      this.outputDirectory = path.join(dirPath);
    } else {
      this.outputDirectory = this.defaultPath;
    }
  }

  public async init() {
    await this.context.stubAuths(this.targetOrg);
    this.targetOrgConnection = await this.targetOrg.getConnection();
    this.sfCommandStubs = stubSfCommandUx(this.context.SANDBOX);
    this.multiStageStub = stubMultiStageUx(this.context.SANDBOX);
    fs.mkdirSync(this.outputDirectory, { recursive: true });
    this.mocks.stubMetadataRetrieve('full');
    this.mocks.restoreStubs();
  }

  public reset() {
    this.context.restore();
    process.removeAllListeners();
    fs.rmSync(this.outputDirectory, { force: true, recursive: true });
    fs.rmSync(this.defaultPath, { force: true, recursive: true });
    fs.rmSync(RETRIEVE_CACHE, { force: true, recursive: true });
    this.mockAuditConfig = { policies: {}, classifications: {} };
    MDAPI.clearCache();
    initDefaultMocks(this.mocks);
  }

  /**
   * Replaces the entire profiles classification
   *
   * @param classifications
   */
  public mockProfileClassifications(classifications: ProfileClassifications): void {
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
  public mockPermSetClassifications(classifications: PermissionSetClassifications): void {
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
  public mockProfileClassification(profileName: string, classification: ProfileClassifications['string']): void {
    this.mockAuditConfig.classifications.profiles ??= { profiles: {} };
    this.mockAuditConfig.classifications.profiles.profiles[profileName] = classification;
  }

  /**
   * Mocks classification of a specific permission set
   *
   * @param permSetName
   * @param classification
   */
  public mockPermSetClassification(permSetName: string, classification: PermissionSetClassifications['string']): void {
    this.mockAuditConfig.classifications.permissionSets ??= { permissionSets: {} };
    this.mockAuditConfig.classifications.permissionSets.permissionSets[permSetName] = classification;
  }

  public mockUserClassification(username: string, classification: UserClassifications['string']): void {
    this.mockAuditConfig.classifications.users ??= { users: {} };
    this.mockAuditConfig.classifications.users.users[username] = classification;
  }
}

/**
 * Initialises default mocks for describes & queries and resets all
 * mocks that were prepared to the default state.
 *
 * @param mocks
 * @returns
 */
function initDefaultMocks(mocks: SfConnectionMocks): SfConnectionMocks {
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
  mocks.prepareMocks(defaults);
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

export function newRuleResult(ruleName?: string): PartialPolicyRuleResult {
  return {
    ruleName: ruleName ?? 'Mock_Rule',
    violations: new Array<PolicyRuleViolation>(),
    mutedViolations: new Array<PolicyRuleViolationMute>(),
    warnings: new Array<RuleComponentMessage>(),
    errors: [],
  };
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
