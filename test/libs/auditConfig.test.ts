import fs from 'node:fs';
import path from 'node:path';
import { Messages } from '@salesforce/core';
import { expect, assert } from 'chai';
import AuditTestContext, { buildAuditConfigPath } from '../mocks/auditTestContext.js';
import AuditConfig from '../../src/libs/conf-init/auditConfig.js';
import StrictPreset from '../../src/libs/conf-init/presets/strict.js';
import LoosePreset from '../../src/libs/conf-init/presets/loose.js';
import { AuditRunConfig, loadAuditConfig, saveAuditConfig } from '../../src/libs/audit-engine/index.js';
import { PermissionRiskLevel, UserPrivilegeLevel } from '../../src/libs/audit-engine/registry/shape/schema.js';
import { AuditInitPresets } from '../../src/libs/conf-init/init.types.js';
import { setRoleInClassification } from '../mocks/testHelpers.js';

const DEFAULT_TEST_OUTPUT_DIR = path.join('tmp', 'test-outputs', 'audit-config');
Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policyclassifications');
const auditRunMessages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'org.audit.run');
const validationMessages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'auditShapeValidation');

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
      const auditConf = await AuditConfig.init($$.coreConnection);

      // Assert
      assert.isDefined(auditConf.shape.userPermissions);
      assert.isDefined(auditConf.shape.customPermissions);
      assert.isDefined(auditConf.inventory.profiles);
      assert.isDefined(auditConf.inventory.permissionSets);
      assert.isDefined(auditConf.inventory.users);
      assert.isDefined(auditConf.policies.profiles);
      assert.isDefined(auditConf.policies.permissionSets);
      assert.isDefined(auditConf.policies.connectedApps);
      assert.isDefined(auditConf.policies.users);
    });

    it('inits full config and saves files to target dir', async () => {
      // Act
      const auditConf = await AuditConfig.init($$.coreConnection);

      // Assert
      assertFullConfig(auditConf);
    });

    it('inits full config and saves files root dir of no target dir is set', async () => {
      // Act
      const auditConf = await AuditConfig.init($$.coreConnection);

      // Assert
      assertFullConfig(auditConf);
    });

    it('inits partial classifications if org does not return custom perms', async () => {
      // Arrange
      $$.mocks.mockCustomPermissions('empty');

      // Act
      const auditConf = await AuditConfig.init($$.coreConnection);

      // Assert
      expect(auditConf.shape.customPermissions).to.be.undefined;
    });

    it('applies the selected preset logic when initialising config', async () => {
      // Act
      const auditConf = await AuditConfig.init($$.coreConnection, { preset: AuditInitPresets.strict });

      // Assert
      assert.isDefined(auditConf.shape.userPermissions);
      const strictPreset = new StrictPreset();
      const testedDefaultPerms = ['UseAnyApiClient', 'CustomizeApplication', 'AuthorApex', 'ModifyMetadata'];
      testedDefaultPerms.forEach((permName) => {
        const perm = auditConf.shape.userPermissions?.[permName];
        assert.isDefined(perm);
        const expectedRiskLevel = strictPreset.initDefault(permName);
        assert.isDefined(expectedRiskLevel);
        expect(perm.classification).to.equal(expectedRiskLevel.classification);
        expect(perm.reason).to.equal(messages.getMessage(permName));
      });
    });

    it('defaults all not explicitly classified perms in loose preset as low', async () => {
      // Act
      const auditConf = await AuditConfig.init($$.coreConnection, { preset: AuditInitPresets.loose });

      // Assert
      assert.isDefined(auditConf.shape.userPermissions);
      const preset = new LoosePreset();
      const allPerms = auditConf.shape.userPermissions;
      Object.entries(allPerms).forEach(([permName, perm]) => {
        const expectedRiskLevel = preset.initDefault(permName);
        assert.isDefined(expectedRiskLevel);
        expect(perm.classification).to.equal(expectedRiskLevel.classification);
      });
    });

    it('initialises only reasons and no classifications with default preset', async () => {
      // Act
      const auditConf = await AuditConfig.init($$.coreConnection, { preset: AuditInitPresets.none });

      // Assert
      assert.isDefined(auditConf.shape.userPermissions);
      const userPerms = auditConf.shape.userPermissions;
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
      const auditConf = await AuditConfig.init($$.coreConnection, { preset: AuditInitPresets.none });

      // Assert
      assert.isDefined(auditConf.shape.userPermissions);
      // these are the permissions from our prod that are part of profiles, but not part of the permset describe
      const missingPermsFromMetadata = [
        'CanApproveUninstalledApps',
        'ManagePackageLicenses',
        'ViewConsumption',
        'ViewFlowUsageAndFlowEventData',
        'AllowObjectDetectionTraining',
      ];
      missingPermsFromMetadata.forEach((permName) => {
        const perm = auditConf.shape.userPermissions?.[permName];
        assert.isDefined(perm);
      });
    });

    it('initialises user classification with active users from org', async () => {
      // Act
      const auditConf = await AuditConfig.init($$.coreConnection);

      // Assert
      assert.isDefined(auditConf.inventory.users);
      assert.isDefined(auditConf.policies.users);
      const userClassification = auditConf.inventory.users;
      const userPolicy = auditConf.policies.users;
      expect(Object.keys(userClassification)).to.deep.equal([
        'guest-user@example.de',
        'test-user-1@example.de',
        'test-user-2@example.de',
      ]);
      expect(userPolicy.options.defaultRoleForMissingUsers).to.equal(UserPrivilegeLevel.STANDARD_USER);
      expect(userPolicy.options.analyseLastNDaysOfLoginHistory).to.equal(30);
    });

    it('initialises profiles classification with all profiles from org', async () => {
      // Act
      const auditConf = await AuditConfig.init($$.coreConnection);

      // Assert
      assert.isDefined(auditConf.inventory.profiles);
      assert.isDefined(auditConf.policies.profiles);
      const profiles = auditConf.inventory.profiles;
      const policy = auditConf.policies.profiles;
      expect(Object.keys(profiles)).to.deep.equal(['Custom Profile', 'System Administrator', 'Standard User']);
      expect(policy.enabled).to.be.true;
    });
  });

  describe('read/write config from files', () => {
    it('loads existing full config', async () => {
      // Act
      const auditConf = loadAuditConfig(buildAuditConfigPath('full-valid'));

      // Assert
      assert.isDefined(auditConf.shape.userPermissions);
      assert.isDefined(auditConf.shape.customPermissions);
      assert.isDefined(auditConf.inventory.profiles);
      assert.isDefined(auditConf.inventory.permissionSets);
      assert.isDefined(auditConf.inventory.users);
      assert.isDefined(auditConf.policies.profiles);
      assert.isDefined(auditConf.policies.permissionSets);
      assert.isDefined(auditConf.policies.connectedApps);
      assert.isDefined(auditConf.policies.users);
    });

    it('loads partial classifications and policies files', async () => {
      // Act
      const auditConf = loadAuditConfig(buildAuditConfigPath('minimal'));

      // Assert
      assert.isDefined(auditConf.shape.userPermissions);
      assert.isDefined(auditConf.inventory.profiles);
      assert.isDefined(auditConf.policies.profiles);
      expect(auditConf.shape.customPermissions).to.be.undefined;
      expect(auditConf.policies.permissionSets).to.be.undefined;
      expect(auditConf.policies.connectedApps).to.be.undefined;
    });

    it('bubbles zod parse exceptions as formatted SfError', async () => {
      // Assert
      const actualFilePath = buildAuditConfigPath(path.join('invalid-schema', 'policies', 'users.yml'));
      const expectedErrorMsg = auditRunMessages.getMessage('error.InvalidConfigFileSchema', [
        actualFilePath,
        'Unrecognized key: "unknownKeyForOptions" in "options"',
      ]);
      expect(() => loadAuditConfig(buildAuditConfigPath('invalid-schema'))).to.throw(expectedErrorMsg);
    });

    it('writes fresh initialised audit config to file', async () => {
      // Act
      const auditConf = await AuditConfig.init($$.coreConnection);
      const saveResult = saveAuditConfig(DEFAULT_TEST_OUTPUT_DIR, auditConf);

      // Assert
      expect(saveResult.acceptedRisks).to.deep.equal({});
      expect(Object.keys(saveResult.policies)).to.have.members([
        'profiles',
        'settings',
        'permissionSets',
        'users',
        'connectedApps',
      ]);
    });

    it('rejects to load audit config if assigned roles do not match custom roles', async () => {
      // Arrange
      const auditConf = await AuditConfig.init($$.coreConnection);
      auditConf.controls.roles = {
        MyOpsRole: {
          permissions: {
            allowedClassifications: [PermissionRiskLevel.HIGH, PermissionRiskLevel.MEDIUM],
          },
        },
        MyUserRole: {
          permissions: {
            allowedClassifications: [PermissionRiskLevel.LOW],
          },
        },
      };
      saveAuditConfig(DEFAULT_TEST_OUTPUT_DIR, auditConf);

      // Assert
      const expectedMsg = validationMessages.getMessage('RoleNotInDefinition', ['Unknown']);
      expect(() => loadAuditConfig(DEFAULT_TEST_OUTPUT_DIR)).to.throw(expectedMsg);
    });

    it('accepts to load audit config if assigned roles match custom roles', async () => {
      // Arrange
      const auditConf = await AuditConfig.init($$.coreConnection);
      auditConf.controls.roles = {
        MyOpsRole: {
          permissions: {
            allowedClassifications: [PermissionRiskLevel.HIGH, PermissionRiskLevel.MEDIUM],
          },
        },
        MyUserRole: {
          permissions: {
            allowedClassifications: [PermissionRiskLevel.LOW],
          },
        },
      };
      setRoleInClassification('MyOpsRole', auditConf.inventory.permissionSets);
      setRoleInClassification('MyUserRole', auditConf.inventory.profiles);
      setRoleInClassification('MyUserRole', auditConf.inventory.users);
      saveAuditConfig(DEFAULT_TEST_OUTPUT_DIR, auditConf);

      // Act
      const loadedConf = loadAuditConfig(DEFAULT_TEST_OUTPUT_DIR);

      // Assert
      assert.isDefined(loadedConf.controls.roles);
      expect(Object.keys(loadedConf.controls.roles)).to.deep.equal(['MyOpsRole', 'MyUserRole']);
    });
  });
});

function assertFullConfig(auditConf: AuditRunConfig) {
  assert.isDefined(auditConf.shape.userPermissions);
  assert.isDefined(auditConf.shape.customPermissions);
  assert.isDefined(auditConf.inventory.profiles);
  assert.isDefined(auditConf.inventory.permissionSets);
  assert.isDefined(auditConf.inventory.users);
  assert.isDefined(auditConf.policies.profiles);
  assert.isDefined(auditConf.policies.permissionSets);
  assert.isDefined(auditConf.policies.connectedApps);
  assert.isDefined(auditConf.policies.users);
}
