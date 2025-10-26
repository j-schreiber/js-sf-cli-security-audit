import fs from 'node:fs';
import path from 'node:path';
import { Messages } from '@salesforce/core';
import { expect, assert } from 'chai';
import AuditTestContext, {
  MOCK_DATA_BASE_PATH,
  parseFileAsJson,
  QUERY_RESULTS_BASE,
} from '../mocks/auditTestContext.js';
import AuditConfig from '../../src/libs/conf-init/auditConfig.js';
import { loadAuditConfig, saveAuditConfig } from '../../src/libs/core/file-mgmt/auditConfigFileManager.js';
import { AuditRunConfig, ConfigFile } from '../../src/libs/core/file-mgmt/schema.js';
import { CUSTOM_PERMS_QUERY } from '../../src/libs/core/constants.js';
import { ProfilesRiskPreset } from '../../src/libs/core/policy-types.js';
import { AuditInitPresets } from '../../src/libs/conf-init/presets.js';

const DEFAULT_TEST_OUTPUT_DIR = path.join('tmp', 'test-outputs', 'audit-config');
Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policyclassifications');

describe('audit config', () => {
  const $$ = new AuditTestContext();

  beforeEach(async () => {
    await $$.init();
  });

  afterEach(async () => {
    $$.reset();
    fs.rmSync(DEFAULT_TEST_OUTPUT_DIR, { recursive: true, force: true });
  });

  function assertFile(expectedPath: string, confFile?: ConfigFile<unknown>) {
    assert.isDefined(confFile?.filePath);
    expect(confFile.filePath).to.equal(expectedPath);
    expect(fs.existsSync(confFile.filePath)).to.be.true;
  }

  describe('initialise new from org', () => {
    it('inits full config', async () => {
      // Act
      const auditConf = await AuditConfig.init($$.targetOrgConnection);

      // Assert
      assert.isDefined(auditConf.classifications.userPermissions);
      assert.isDefined(auditConf.classifications.customPermissions);
      assert.isDefined(auditConf.policies.Profiles);
      assert.isDefined(auditConf.policies.PermissionSets);
      assert.isDefined(auditConf.policies.ConnectedApps);
      expect(auditConf.classifications.userPermissions.filePath).to.be.undefined;
      expect(auditConf.classifications.customPermissions.filePath).to.be.undefined;
      expect(auditConf.policies.Profiles.filePath).to.be.undefined;
      expect(auditConf.policies.PermissionSets.filePath).to.be.undefined;
      expect(auditConf.policies.ConnectedApps.filePath).to.be.undefined;
    });

    it('inits full config and saves files to target dir', async () => {
      // Act
      const outputDir = path.join(DEFAULT_TEST_OUTPUT_DIR, 'test-1');
      const auditConf = await AuditConfig.init($$.targetOrgConnection, { targetDir: outputDir });

      // Assert
      assert.isDefined(auditConf.classifications.userPermissions);
      assert.isDefined(auditConf.classifications.customPermissions);
      assert.isDefined(auditConf.policies.Profiles);
      assert.isDefined(auditConf.policies.PermissionSets);
      assert.isDefined(auditConf.policies.ConnectedApps);
      // expect(auditConf.classifications.userPermissions.content).to.equal(417);
      // expect(auditConf.classifications.customPermissions.getPermissionNames().length).to.equal(3);
      assertFile(
        path.join(outputDir, 'classifications', 'userPermissions.yml'),
        auditConf.classifications.userPermissions
      );
      assertFile(
        path.join(outputDir, 'classifications', 'customPermissions.yml'),
        auditConf.classifications.customPermissions
      );
      assertFile(path.join(outputDir, 'policies', 'profiles.yml'), auditConf.policies.Profiles);
      assertFile(path.join(outputDir, 'policies', 'permissionSets.yml'), auditConf.policies.PermissionSets);
      assertFile(path.join(outputDir, 'policies', 'connectedApps.yml'), auditConf.policies.ConnectedApps);
    });

    it('inits partial classifications if org does not return custom perms', async () => {
      // Arrange
      $$.mocks.setQueryMock(CUSTOM_PERMS_QUERY, path.join(QUERY_RESULTS_BASE, 'empty.json'));
      // Act
      const auditConf = await AuditConfig.init($$.targetOrgConnection);

      // Assert
      expect(auditConf.classifications.customPermissions).to.be.undefined;
    });

    it('applies the selected preset logic when initialising config', async () => {
      // Act
      const auditConf = await AuditConfig.init($$.targetOrgConnection, { preset: AuditInitPresets.strict });

      // Assert
      assert.isDefined(auditConf.classifications.userPermissions);
      // later will replace with list that checks all perms from the preset
      const anyApiClientPerm = auditConf.classifications.userPermissions.content.permissions.UseAnyApiClient;
      assert.isDefined(anyApiClientPerm);
      expect(anyApiClientPerm.classification).to.equal('Blocked');
      expect(anyApiClientPerm.reason).to.equal(messages.getMessage('UseAnyApiClient'));
    });
  });

  describe('load config from directory', () => {
    it('loads existing full config', async () => {
      // Act
      const testDir = path.join(MOCK_DATA_BASE_PATH, 'audit-configs', 'full-valid');
      const auditConf = loadAuditConfig(testDir);

      // Assert
      assert.isDefined(auditConf.classifications.userPermissions);
      assert.isDefined(auditConf.classifications.customPermissions);
      assert.isDefined(auditConf.policies.Profiles);
      assert.isDefined(auditConf.policies.PermissionSets);
      assert.isDefined(auditConf.policies.ConnectedApps);
      expect(auditConf.classifications.userPermissions.filePath).not.to.be.undefined;
      expect(auditConf.classifications.customPermissions.filePath).not.to.be.undefined;
      expect(auditConf.policies.Profiles.filePath).not.to.be.undefined;
      expect(auditConf.policies.PermissionSets.filePath).not.to.be.undefined;
      expect(auditConf.policies.ConnectedApps.filePath).not.to.be.undefined;
    });

    it('loads partial classifications and policies files', async () => {
      // Act
      const testDir = path.join(MOCK_DATA_BASE_PATH, 'audit-configs', 'partial-valid');
      const auditConf = loadAuditConfig(testDir);

      // Assert
      assert.isDefined(auditConf.classifications.userPermissions);
      assert.isDefined(auditConf.policies.Profiles);
      expect(auditConf.classifications.customPermissions).to.be.undefined;
      expect(auditConf.policies.PermissionSets).to.be.undefined;
      expect(auditConf.policies.ConnectedApps).to.be.undefined;
      expect(auditConf.classifications.userPermissions.filePath).not.to.be.undefined;
      expect(auditConf.policies.Profiles.filePath).not.to.be.undefined;
    });
  });

  describe('saves', () => {
    it('new files at emtpy location for new audit conf', async () => {
      // Act
      const mockAudit = parseFileAsJson<AuditRunConfig>('audit-lib-results', 'init', 'full.json');
      const testDir = path.join(DEFAULT_TEST_OUTPUT_DIR, 'save-test-1');
      saveAuditConfig(testDir, mockAudit);

      // Assert
      const expectedUserPermsPath = path.join(testDir, 'classifications', 'userPermissions.yml');
      expect(mockAudit.classifications.userPermissions?.filePath).to.equal(expectedUserPermsPath);
      expect(fs.existsSync(expectedUserPermsPath)).to.be.true;
      const expectedCustomPermsPath = path.join(testDir, 'classifications', 'customPermissions.yml');
      expect(mockAudit.classifications.customPermissions?.filePath).to.equal(expectedCustomPermsPath);
      expect(fs.existsSync(expectedCustomPermsPath)).to.be.true;
      expect(fs.existsSync(path.join(testDir, 'classifications', 'customPermissions.yml'))).to.be.true;
      expect(fs.existsSync(path.join(testDir, 'policies', 'profiles.yml'))).to.be.true;
      expect(fs.existsSync(path.join(testDir, 'policies', 'permissionSets.yml'))).to.be.true;
    });

    it('updated files at existing location with new values', async () => {
      // Arrange
      const mockAudit = parseFileAsJson<AuditRunConfig>('audit-lib-results', 'init', 'minimal.json');
      const testDir = path.join(DEFAULT_TEST_OUTPUT_DIR, 'save-test-2');
      saveAuditConfig(testDir, mockAudit);

      // Act
      Object.values(mockAudit.policies.Profiles!.content.profiles).forEach((profile) => {
        // eslint-disable-next-line no-param-reassign
        profile.preset = ProfilesRiskPreset.ADMIN;
      });
      saveAuditConfig(testDir, mockAudit);

      // Assert
      const updatedConf = loadAuditConfig(testDir);
      Object.values(updatedConf.policies.Profiles!.content.profiles).forEach((profile) => {
        expect(profile.preset).to.equal(ProfilesRiskPreset.ADMIN);
      });
    });
  });
});
