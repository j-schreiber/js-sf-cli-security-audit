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
const USER_PERMS_COUNT = 486;

function buildPath(dirName: string) {
  return path.join(TEST_DIR_BASE_PATH, dirName);
}

describe('audit run', () => {
  const $$ = new AuditTestContext();

  beforeEach(async () => {
    await $$.init();
  });

  afterEach(async () => {
    $$.reset();
    fs.rmSync(path.join(TEST_DIR_BASE_PATH, 'tmp-1'), { recursive: true, force: true });
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
  });

  describe('initialise new from org', () => {
    it('initialises new config and writes files to target logation', async () => {
      // Arrange
      $$.mocks.setQueryMock(
        CUSTOM_PERMS_QUERY,
        path.join('test', 'mocks', 'data', 'queryResults', 'customPermissions.json')
      );
      const testPath = path.join(TEST_DIR_BASE_PATH, 'tmp-1');

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
      assert.isDefined(auditResult.policies.Profiles);
      assert.isDefined(auditResult.policies.PermissionSets);
      expect(Object.keys(auditResult.policies.Profiles.executedRules)).to.deep.equal(['EnforceClassificationPresets']);
      expect(Object.keys(auditResult.policies.PermissionSets.executedRules)).to.deep.equal([
        'EnforceClassificationPresets',
      ]);
    });
  });
});
