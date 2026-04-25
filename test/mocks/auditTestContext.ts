import fs, { PathLike } from 'node:fs';
import path from 'node:path';
import { SinonSandbox } from 'sinon';
import { Connection } from '@salesforce/core';
import { stubSfCommandUx, stubSpinner } from '@salesforce/sf-plugins-core';
import { MockTestOrgData, TestContext } from '@salesforce/core/testSetup';
import { AuditRunConfig } from '../../src/libs/audit-engine/index.js';
import {
  PermissionSetClassifications,
  ProfileClassifications,
  PermissionControls,
  UserClassifications,
  ComposableRolesControl,
  PermissionClassifications,
} from '../../src/libs/audit-engine/registry/shape/schema.js';
import AuditRunMultiStageOutput from '../../src/ux/auditRunMultiStage.js';
import { MDAPI, OrgDescribe } from '../../src/salesforce/index.js';
import { RETRIEVE_CACHE } from '../../src/salesforce/mdapi/constants.js';
import { SUPPORTED_ENV_VARS } from '../../src/ux/environment.js';
import SfConnection from '../../src/salesforce/connection.js';
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
  public coreConnection!: Connection;
  public targetOrgConnection!: SfConnection;
  public outputDirectory: PathLike;
  public defaultPath = path.join('my-test-org');
  public sfCommandStubs!: ReturnType<typeof stubSfCommandUx>;
  public multiStageStub!: ReturnType<typeof stubMultiStageUx>;
  public sfSpinnerStub!: ReturnType<typeof stubSpinner>;
  public mocks: SfConnectionMocks;
  public mockAuditConfig: AuditRunConfig = { policies: {}, shape: {}, inventory: {}, acceptedRisks: {}, controls: {} };
  private originalCwd;

  public constructor(dirPath?: string) {
    this.originalCwd = process.cwd();
    this.context = new TestContext();
    this.targetOrg = new MockTestOrgData();
    this.targetOrg.instanceUrl = 'https://test-org.my.salesforce.com';
    this.mocks = new SfConnectionMocks(this.context);
    initDefaultMocks(this.mocks);
    if (dirPath) {
      this.outputDirectory = path.join(dirPath);
    } else {
      this.outputDirectory = this.defaultPath;
    }
  }

  public async init() {
    await this.context.stubAuths(this.targetOrg);
    this.coreConnection = await this.targetOrg.getConnection();
    this.targetOrgConnection = new SfConnection(this.coreConnection);
    // comment out this line to see console output in unit tests
    this.sfCommandStubs = stubSfCommandUx(this.context.SANDBOX);
    this.multiStageStub = stubMultiStageUx(this.context.SANDBOX);
    this.sfSpinnerStub = stubSpinner(this.context.SANDBOX);
    fs.mkdirSync(this.outputDirectory, { recursive: true });
    await this.mocks.stubMetadataRetrieve('full');
    this.mocks.restoreStubs();
  }

  public reset() {
    this.context.restore();
    process.chdir(this.originalCwd);
    OrgDescribe.orgCache.clear();
    process.removeAllListeners();
    fs.rmSync(this.outputDirectory, { force: true, recursive: true });
    fs.rmSync(this.defaultPath, { force: true, recursive: true });
    fs.rmSync(RETRIEVE_CACHE, { force: true, recursive: true });
    this.mockAuditConfig = { policies: {}, shape: {}, inventory: {}, acceptedRisks: {}, controls: {} };
    MDAPI.clearCache();
    resetAllEnvironmentVars();
    initDefaultMocks(this.mocks);
  }

  /**
   * Replaces all role controls in the mock audit config.
   *
   * @param roles
   */
  public mockRoles(roles: ComposableRolesControl): void {
    this.mockAuditConfig.controls.roles = roles;
  }

  /**
   * Replaces the definition of one role control in the mock audit config
   * without affecting the other roles.
   *
   * @param roleName
   * @param role
   */
  public mockRole(roleName: string, role: ComposableRolesControl['string']): void {
    if (!this.mockAuditConfig.controls.roles) {
      this.mockAuditConfig.controls.roles = {};
    }
    this.mockAuditConfig.controls.roles[roleName] = role;
  }

  /**
   * Replaces the permission controls (formerly role definitions)
   *
   * @param roles
   */
  public mockPermissionControls(perms?: PermissionControls): void {
    this.mockAuditConfig.controls.permissions = perms;
  }

  /**
   * Replaces the entire profiles classification
   *
   * @param classifications
   */
  public mockProfileClassifications(classifications: ProfileClassifications): void {
    this.mockAuditConfig.inventory.profiles = undefined;
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
    this.mockAuditConfig.inventory.permissionSets = undefined;
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
    this.mockAuditConfig.inventory.profiles ??= {};
    this.mockAuditConfig.inventory.profiles[profileName] = classification;
  }

  /**
   * Mocks classification of a specific permission set
   *
   * @param permSetName
   * @param classification
   */
  public mockPermSetClassification(permSetName: string, classification: PermissionSetClassifications['string']): void {
    this.mockAuditConfig.inventory.permissionSets ??= {};
    this.mockAuditConfig.inventory.permissionSets[permSetName] = classification;
  }

  /**
   * Replaces the complete user classifications in the mock audit config
   *
   * @param classifications
   */
  public mockUserClassifications(classifications: UserClassifications): void {
    this.mockAuditConfig.inventory.users = undefined;
    Object.entries(classifications).forEach(([permSetName, classification]) => {
      this.mockUserClassification(permSetName, classification);
    });
  }

  public mockUserClassification(username: string, classification: UserClassifications['string']): void {
    this.mockAuditConfig.inventory.users ??= {};
    this.mockAuditConfig.inventory.users[username] = classification;
  }

  public mockUserPermissions(classifications: PermissionClassifications): void {
    this.mockAuditConfig.shape.userPermissions = classifications;
  }

  public mockCustomPermissions(classifications: PermissionClassifications): void {
    this.mockAuditConfig.shape.customPermissions = classifications;
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
  mocks.prepareMocks(defaults);
  mocks.mockCustomPermissions('custom-permissions');
  // active users, but wipe all permission set assignments
  mocks.mockUsers('active-user-details', (record) => ({ ...record, PermissionSetAssignments: null }));
  mocks.mockProfiles('profiles');
  mocks.mockProfiles('profiles', ['System Administrator', 'Standard User', 'Custom Profile']);
  mocks.mockProfiles('admin-and-standard-profiles', ['System Administrator', 'Standard User']);
  mocks.mockProfileResolve('System Administrator', 'admin-profile-with-metadata');
  mocks.mockProfileResolve('Standard User', 'standard-profile-with-metadata');
  mocks.mockProfileResolve('Guest User Profile', 'empty');
  mocks.mockProfileResolve('Custom Profile', 'empty');
  mocks.mockExternalClientApps('empty');
  mocks.mockExternalClientAppOAuthPolicies('empty');
  mocks.mockLoginHistory('empty');
  // 14 days is option config in "full-valid" user policy
  mocks.mockLoginHistory('empty', 14);
  mocks.mockOAuthTokens('empty');
  mocks.mockConnectedApps('empty');
  mocks.mockPermissionSets('empty');
  return mocks;
}

function resetAllEnvironmentVars() {
  const allVars = Object.keys(SUPPORTED_ENV_VARS);
  for (const envVar of allVars) {
    delete process.env[envVar];
  }
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
