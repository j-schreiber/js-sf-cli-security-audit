import path from 'node:path';
import { expect, assert } from 'chai';
import AuditTestContext from '../mocks/auditTestContext.js';
import AuditRun from '../../src/libs/policies/auditRun.js';

const TEST_DIR_BASE_PATH = path.join('test', 'mocks', 'data', 'audit-configs');

function buildPath(dirName: string) {
  return path.join(TEST_DIR_BASE_PATH, dirName);
}

describe('audit run', () => {
  const $$ = new AuditTestContext();

  beforeEach(async () => {
    $$.init();
  });

  afterEach(async () => {
    $$.reset();
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
      assert.isDefined(audit.configs.policies.profiles);
      assert.isDefined(audit.configs.policies.permissionSets);
      expect(audit.configs.classifications.customPermissions.filePath).to.equal(
        path.join(dirPath, 'classification', 'customPermissions.yml')
      );
      const customPerms = Object.entries(audit.configs.classifications.customPermissions.content.permissions);
      expect(customPerms.length).to.equal(2);
      expect(audit.configs.classifications.userPermissions.filePath).to.equal(
        path.join(dirPath, 'classification', 'userPermissions.yml')
      );
      const userPerms = Object.entries(audit.configs.classifications.userPermissions.content.permissions);
      expect(userPerms.length).to.equal(486);
      expect(audit.configs.policies.profiles.filePath).to.equal(path.join(dirPath, 'policies', 'profiles.yml'));
      const profiles = Object.entries(audit.configs.policies.profiles.content.profiles);
      expect(profiles.length).to.equal(4);
      expect(audit.configs.policies.permissionSets.filePath).to.equal(
        path.join(dirPath, 'policies', 'permissionSets.yml')
      );
      const permSets = Object.entries(audit.configs.policies.permissionSets.content.permissionSets);
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
      expect(audit.configs.policies.profiles).not.to.be.undefined;
      expect(audit.configs.policies.permissionSets).to.be.undefined;
    });

    it('successfully loads and resolves empty audit run', async () => {
      // Arrange
      const dirPath = buildPath('empty');

      // Act
      const audit = AuditRun.load(dirPath);

      // Assert
      expect(audit.configs.classifications.customPermissions).to.be.undefined;
      expect(audit.configs.classifications.userPermissions).to.be.undefined;
      expect(audit.configs.policies.profiles).to.be.undefined;
      expect(audit.configs.policies.permissionSets).to.be.undefined;
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
      expect(Object.keys(auditResult.policies.Profiles.executedRules)).to.deep.equal(['EnforceClassificationPresets']);
    });
  });
});
