import fs from 'node:fs';
import path from 'node:path';
import { expect, assert } from 'chai';
import AuditTestContext from '../mocks/auditTestContext.js';
import AuditRun from '../../src/libs/policies/auditRun.js';
import {
  CUSTOM_PERMISSIONS_PATH,
  PERMSET_POLICY_PATH,
  PROFILE_POLICY_PATH,
  USER_PERMISSIONS_PATH,
} from '../../src/libs/config/filePaths.js';
import { CUSTOM_PERMS_QUERY } from '../../src/libs/config/queries.js';

const TEST_DIR_BASE_PATH = path.join('test', 'mocks', 'data', 'audit-configs');
// const QUERIES_BASE_PATH = path.join('test', 'mocks', 'data', 'queryResults');
const DEFAULT_TEST_OUTPUT_DIR = path.join(TEST_DIR_BASE_PATH, 'tmp-1');
const USER_PERMS_COUNT = 486;

function buildPath(dirName: string) {
  return path.join(TEST_DIR_BASE_PATH, dirName);
}

// function queryResultPath(fileName: string) {
//   return path.join(QUERIES_BASE_PATH, fileName);
// }

describe('audit run', () => {
  const $$ = new AuditTestContext();

  beforeEach(async () => {
    await $$.init();
  });

  afterEach(async () => {
    $$.reset();
    fs.rmSync(DEFAULT_TEST_OUTPUT_DIR, { recursive: true, force: true });
  });

  describe('loading', () => {
    it('successfully loads and resolves full audit run with all classifications and policies', async () => {
      // Arrange
      const dirPath = buildPath('full-valid');

      // Act
      const audit = AuditRun.load(dirPath);

      // Assert
      assert.isDefined(audit.configs.classifications.customPermissions);
      assert.isDefined(audit.configs.classifications.userPermissions);
      assert.isDefined(audit.configs.policies.Profiles);
      assert.isDefined(audit.configs.policies.PermissionSets);
      expect(audit.configs.classifications.customPermissions.filePath).to.equal(
        path.join(dirPath, 'classification', 'customPermissions.yml')
      );
      const customPerms = Object.entries(audit.configs.classifications.customPermissions.content.permissions);
      expect(customPerms.length).to.equal(2);
      expect(audit.configs.classifications.userPermissions.filePath).to.equal(
        path.join(dirPath, 'classification', 'userPermissions.yml')
      );
      const userPerms = Object.entries(audit.configs.classifications.userPermissions.content.permissions);
      expect(userPerms.length).to.equal(USER_PERMS_COUNT);
      expect(audit.configs.policies.Profiles.filePath).to.equal(path.join(dirPath, 'policies', 'profiles.yml'));
      const profiles = Object.entries(audit.configs.policies.Profiles.content.profiles);
      expect(profiles.length).to.equal(4);
      expect(audit.configs.policies.PermissionSets.filePath).to.equal(
        path.join(dirPath, 'policies', 'permissionSets.yml')
      );
      const permSets = Object.entries(audit.configs.policies.PermissionSets.content.permissionSets);
      expect(permSets.length).to.equal(7);
    });

    it('successfully loads and resolves partial audit run', async () => {
      // Arrange
      const dirPath = buildPath('partial-valid');

      // Act
      const audit = AuditRun.load(dirPath);

      // Assert
      expect(audit.configs.classifications.customPermissions).to.be.undefined;
      expect(audit.configs.classifications.userPermissions).not.to.be.undefined;
      expect(audit.configs.policies.Profiles).not.to.be.undefined;
      expect(audit.configs.policies.PermissionSets).to.be.undefined;
    });

    it('successfully loads and resolves empty audit run', async () => {
      // Arrange
      const dirPath = buildPath('empty');

      // Act
      const audit = AuditRun.load(dirPath);

      // Assert
      expect(audit.configs.classifications.customPermissions).to.be.undefined;
      expect(audit.configs.classifications.userPermissions).to.be.undefined;
      expect(audit.configs.policies.Profiles).to.be.undefined;
      expect(audit.configs.policies.PermissionSets).to.be.undefined;
    });

    it('loads audit run config from root directory, if path is nullish', async () => {
      // Arrange
      fs.cpSync(buildPath('full-valid'), '.', { recursive: true });

      // Act
      const nullishDirValues = [undefined, null, '', '.'];
      nullishDirValues.forEach((dirPath) => {
        const audit = AuditRun.load(dirPath);

        // Assert
        assert.isDefined(audit.configs.classifications.userPermissions, 'for dirPath: ' + dirPath);
        assert.isDefined(audit.configs.classifications.customPermissions, 'for dirPath: ' + dirPath);
        assert.isDefined(audit.configs.policies.PermissionSets, 'for dirPath: ' + dirPath);
        assert.isDefined(audit.configs.policies.Profiles, 'for dirPath: ' + dirPath);
      });

      // Cleanup
      fs.rmSync('classification', { recursive: true });
      fs.rmSync('policies', { recursive: true });
    });
  });

  describe('initialise new from org', () => {
    it('initialises new config and writes files to target logation', async () => {
      // Arrange
      $$.mocks.setQueryMock(
        CUSTOM_PERMS_QUERY,
        path.join('test', 'mocks', 'data', 'queryResults', 'customPermissions.json')
      );
      const testPath = DEFAULT_TEST_OUTPUT_DIR;

      // Act
      const conf = await AuditRun.initialiseNewConfig(await $$.targetOrg.getConnection(), { directoryPath: testPath });

      // Assert
      assert.isDefined(conf.classifications.userPermissions);
      expect(conf.classifications.userPermissions.filePath).to.equal(path.join(testPath, USER_PERMISSIONS_PATH));
      const userPerms = Object.entries(conf.classifications.userPermissions.content.permissions);
      expect(userPerms.length).to.equal(417);
      assert.isDefined(conf.classifications.customPermissions);
      expect(conf.classifications.customPermissions.filePath).to.equal(path.join(testPath, CUSTOM_PERMISSIONS_PATH));
      const customPerms = Object.entries(conf.classifications.customPermissions.content.permissions);
      expect(customPerms.length).to.equal(3);
      assert.isDefined(conf.policies.Profiles);
      expect(conf.policies.Profiles.filePath).to.equal(path.join(testPath, PROFILE_POLICY_PATH));
      assert.isDefined(conf.policies.PermissionSets);
      expect(conf.policies.PermissionSets.filePath).to.equal(path.join(testPath, PERMSET_POLICY_PATH));
    });

    it('removes line breaks in perm labels when adding the permissions', async () => {
      // Arrange
      // for some reason, the labels on some of the Permissions* fields on Permission set
      // have unnecessary line breaks, which causes permissions to be initialised like this
      // {
      //   label: 'Associate Releases and Change Requests\n        ',
      //   classification: 'Unknown',
      //   reason: undefined
      // }
      $$.mocks.setDescribeMock(
        'PermissionSet',
        path.join('test', 'mocks', 'data', 'describeResults', 'PermissionSetWithLineBreaks.json')
      );

      // Act
      const conf = await AuditRun.initialiseNewConfig(await $$.targetOrg.getConnection(), {
        directoryPath: DEFAULT_TEST_OUTPUT_DIR,
      });

      // Assert
      assert.isDefined(conf.classifications.userPermissions);
      expect(conf.classifications.userPermissions.content.permissions['EmailMass'].label).to.equal('Mass Email');
      expect(conf.classifications.userPermissions.content.permissions['EmailSingle'].label).to.equal('Send Email');
    });

    it('initialises connected apps policy with all registered rules', async () => {
      // Act
      const conf = await AuditRun.initialiseNewConfig(await $$.targetOrg.getConnection(), {
        directoryPath: DEFAULT_TEST_OUTPUT_DIR,
      });

      // Assert
      assert.isDefined(conf.policies.ConnectedApps);
      expect(fs.existsSync(conf.policies.ConnectedApps.filePath!)).to.be.true;
    });
  });

  describe('execution', () => {
    it('executes all loaded policies', async () => {
      // Arrange
      const dirPath = buildPath('full-valid');
      const audit = AuditRun.load(dirPath);

      // Act
      const auditResult = await audit.execute(await $$.targetOrg.getConnection());

      // Assert
      expect(auditResult.isCompliant).to.be.true;
      assert.isDefined(auditResult.policies);
      assert.isDefined(auditResult.policies.Profiles);
      assert.isDefined(auditResult.policies.PermissionSets);
      expect(auditResult.policies.Profiles.isCompliant).to.be.true;
      expect(auditResult.policies.PermissionSets.isCompliant).to.be.true;
      expect(Object.keys(auditResult.policies.Profiles.executedRules)).to.deep.equal([
        'EnforceUserPermissionClassifications',
      ]);
      expect(Object.keys(auditResult.policies.PermissionSets.executedRules)).to.deep.equal([
        'EnforceUserPermissionClassifications',
      ]);
    });

    it('reports non-compliance if one policy is not compliant', async () => {
      // Arrange
      const dirPath = buildPath('non-compliant');
      const audit = AuditRun.load(dirPath);

      // Act
      const auditResult = await audit.execute(await $$.targetOrg.getConnection());

      // Assert
      expect(auditResult.isCompliant).to.be.false;
      assert.isDefined(auditResult.policies);
      assert.isDefined(auditResult.policies.Profiles);
      expect(auditResult.policies.Profiles.isCompliant).to.be.false;
      assert.isDefined(auditResult.policies.Profiles.executedRules.EnforceUserPermissionClassifications);
      expect(auditResult.policies.Profiles.executedRules.EnforceUserPermissionClassifications.isCompliant).to.be.false;
    });
  });
});
