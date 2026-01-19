import fs from 'node:fs';
import path from 'node:path';
import { Messages } from '@salesforce/core';
import { expect, assert } from 'chai';
import AuditTestContext, { buildAuditConfigPath } from '../mocks/auditTestContext.js';
import AuditConfig from '../../src/libs/conf-init/auditConfig.js';
import StrictPreset from '../../src/libs/conf-init/presets/strict.js';
import LoosePreset from '../../src/libs/conf-init/presets/loose.js';
import { AuditRunConfig, ConfigFileManager } from '../../src/libs/audit-engine/index.js';
import { PermissionRiskLevel, UserPrivilegeLevel } from '../../src/libs/audit-engine/registry/shape/schema.js';
import { AuditInitPresets } from '../../src/libs/conf-init/init.types.js';

const DEFAULT_TEST_OUTPUT_DIR = path.join('tmp', 'test-outputs', 'audit-config');
Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policyclassifications');
const auditRunMessages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'org.audit.run');

function loadAuditConfig(dirPath: string): AuditRunConfig {
  return ConfigFileManager.parse(dirPath);
}

describe('audit config', () => {
  const $$ = new AuditTestContext();

  beforeEach(async () => {
    await $$.init();
  });

  afterEach(async () => {
    $$.reset();
    fs.rmSync(DEFAULT_TEST_OUTPUT_DIR, { recursive: true, force: true });
    fs.rmSync('classifications', { recursive: true, force: true });
    fs.rmSync('policies', { recursive: true, force: true });
  });

  describe('initialise new from org', () => {
    it('inits full config', async () => {
      // Act
      const auditConf = await AuditConfig.init($$.targetOrgConnection);

      // Assert
      assert.isDefined(auditConf.classifications.userPermissions);
      assert.isDefined(auditConf.classifications.customPermissions);
      assert.isDefined(auditConf.classifications.profiles);
      assert.isDefined(auditConf.classifications.permissionSets);
      assert.isDefined(auditConf.classifications.users);
      assert.isDefined(auditConf.policies.profiles);
      assert.isDefined(auditConf.policies.permissionSets);
      assert.isDefined(auditConf.policies.connectedApps);
      assert.isDefined(auditConf.policies.users);
    });

    it('inits full config and saves files to target dir', async () => {
      // Act
      const auditConf = await AuditConfig.init($$.targetOrgConnection);

      // Assert
      assertFullConfig(auditConf);
    });

    it('inits full config and saves files root dir of no target dir is set', async () => {
      // Act
      const auditConf = await AuditConfig.init($$.targetOrgConnection);

      // Assert
      assertFullConfig(auditConf);
    });

    it('inits partial classifications if org does not return custom perms', async () => {
      // Arrange
      $$.mocks.mockCustomPermissions('empty');

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
      const strictPreset = new StrictPreset();
      const testedDefaultPerms = ['UseAnyApiClient', 'CustomizeApplication', 'AuthorApex', 'ModifyMetadata'];
      testedDefaultPerms.forEach((permName) => {
        const perm = auditConf.classifications.userPermissions?.permissions[permName];
        assert.isDefined(perm);
        const expectedRiskLevel = strictPreset.initDefault(permName);
        assert.isDefined(expectedRiskLevel);
        expect(perm.classification).to.equal(expectedRiskLevel.classification);
        expect(perm.reason).to.equal(messages.getMessage(permName));
      });
    });

    it('defaults all not explicitly classified perms in loose preset as low', async () => {
      // Act
      const auditConf = await AuditConfig.init($$.targetOrgConnection, { preset: AuditInitPresets.loose });

      // Assert
      assert.isDefined(auditConf.classifications.userPermissions);
      const preset = new LoosePreset();
      const allPerms = auditConf.classifications.userPermissions?.permissions;
      Object.entries(allPerms).forEach(([permName, perm]) => {
        const expectedRiskLevel = preset.initDefault(permName);
        assert.isDefined(expectedRiskLevel);
        expect(perm.classification).to.equal(expectedRiskLevel.classification);
      });
    });

    it('initialises only reasons and no classifications with default preset', async () => {
      // Act
      const auditConf = await AuditConfig.init($$.targetOrgConnection, { preset: AuditInitPresets.none });

      // Assert
      assert.isDefined(auditConf.classifications.userPermissions);
      const userPerms = auditConf.classifications.userPermissions?.permissions;
      Object.values(userPerms).forEach((perm) => {
        expect(perm.classification).to.equal(PermissionRiskLevel.UNKNOWN);
      });
      const selectedPermsWithReason = ['UseAnyApiClient', 'CustomizeApplication', 'AuthorApex', 'ModifyMetadata'];
      selectedPermsWithReason.forEach((permName) => {
        const perm = userPerms[permName];
        assert.isDefined(perm);
        expect(perm.reason).to.equal(messages.getMessage(permName));
      });
    });

    it('initialises assigned permissions that are not present in describes', async () => {
      // Arrange
      // it appears that some permissions can be assigned (and are available in metadata / source)
      // but they are NOT present in the permission set / profile describe. The most prominent example
      // is the new CanApproveUninstalledApps permission (the corresponding field would have been
      // PermissionsCanApproveUninstalledApps, which does not exist).
      // To remedy that, we parse all profiles and all assigned perms and add any used permissions.

      // Act
      const auditConf = await AuditConfig.init($$.targetOrgConnection, { preset: AuditInitPresets.none });

      // Assert
      assert.isDefined(auditConf.classifications.userPermissions);
      // these are the permissions from our prod that are part of profiles, but not part of the permset describe
      const missingPermsFromMetadata = [
        'CanApproveUninstalledApps',
        'ManagePackageLicenses',
        'ViewConsumption',
        'ViewFlowUsageAndFlowEventData',
        'AllowObjectDetectionTraining',
      ];
      missingPermsFromMetadata.forEach((permName) => {
        const perm = auditConf.classifications.userPermissions?.permissions[permName];
        assert.isDefined(perm);
      });
    });

    it('initialises user classification with active users from org', async () => {
      // Act
      const auditConf = await AuditConfig.init($$.targetOrgConnection);

      // Assert
      assert.isDefined(auditConf.classifications.users);
      assert.isDefined(auditConf.policies.users);
      const userClassification = auditConf.classifications.users;
      const userPolicy = auditConf.policies.users;
      expect(Object.keys(userClassification.users)).to.deep.equal([
        'guest-user@example.de',
        'test-user-1@example.de',
        'test-user-2@example.de',
      ]);
      expect(userPolicy.options.defaultRoleForMissingUsers).to.equal(UserPrivilegeLevel.STANDARD_USER);
    });

    it('initialises profiles classification with all profiles from org', async () => {
      // Act
      const auditConf = await AuditConfig.init($$.targetOrgConnection);

      // Assert
      assert.isDefined(auditConf.classifications.profiles);
      assert.isDefined(auditConf.policies.profiles);
      const classification = auditConf.classifications.profiles;
      const policy = auditConf.policies.profiles;
      expect(Object.keys(classification.profiles)).to.deep.equal([
        'Custom Profile',
        'System Administrator',
        'Standard User',
      ]);
      expect(policy.enabled).to.be.true;
    });
  });

  describe('load config from directory', () => {
    it('loads existing full config', async () => {
      // Act
      const auditConf = loadAuditConfig(buildAuditConfigPath('full-valid'));

      // Assert
      assert.isDefined(auditConf.classifications.userPermissions);
      assert.isDefined(auditConf.classifications.customPermissions);
      assert.isDefined(auditConf.classifications.profiles);
      assert.isDefined(auditConf.classifications.permissionSets);
      assert.isDefined(auditConf.classifications.users);
      assert.isDefined(auditConf.policies.profiles);
      assert.isDefined(auditConf.policies.permissionSets);
      assert.isDefined(auditConf.policies.connectedApps);
      assert.isDefined(auditConf.policies.users);
    });

    it('loads partial classifications and policies files', async () => {
      // Act
      const auditConf = loadAuditConfig(buildAuditConfigPath('minimal'));

      // Assert
      assert.isDefined(auditConf.classifications.userPermissions);
      assert.isDefined(auditConf.classifications.profiles);
      assert.isDefined(auditConf.policies.profiles);
      expect(auditConf.classifications.customPermissions).to.be.undefined;
      expect(auditConf.policies.permissionSets).to.be.undefined;
      expect(auditConf.policies.connectedApps).to.be.undefined;
    });

    it('bubbles zod parse exceptions as formatted SfError', async () => {
      // Assert
      const expectedErrorMsg = auditRunMessages.getMessage('error.InvalidConfigFileSchema', [
        'users.yml',
        'Unrecognized key: "unknownKeyForOptions" in "options"',
      ]);
      expect(() => loadAuditConfig(buildAuditConfigPath('invalid-schema'))).to.throw(expectedErrorMsg);
    });
  });
});

function assertFullConfig(auditConf: AuditRunConfig) {
  assert.isDefined(auditConf.classifications.userPermissions);
  assert.isDefined(auditConf.classifications.customPermissions);
  assert.isDefined(auditConf.classifications.profiles);
  assert.isDefined(auditConf.classifications.permissionSets);
  assert.isDefined(auditConf.classifications.users);
  assert.isDefined(auditConf.policies.profiles);
  assert.isDefined(auditConf.policies.permissionSets);
  assert.isDefined(auditConf.policies.connectedApps);
  assert.isDefined(auditConf.policies.users);
}
