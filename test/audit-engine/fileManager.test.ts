import fs from 'node:fs';
import path from 'node:path';
import z from 'zod';
import { assert, expect } from 'chai';
import { Messages } from '@salesforce/core';
import FileManager from '../../src/libs/audit-engine/file-manager/fileManager.js';
import { AuditConfigFileSchema } from '../../src/libs/audit-engine/file-manager/fileManager.types.js';
import { MOCK_DATA_BASE_PATH } from '../mocks/data/paths.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'org.audit.run');

const PolicyRuleConfigSchema = z.object({
  enabled: z.boolean().default(false),
  options: z.unknown().optional(),
});

const RuleMapSchema = z.record(z.string(), PolicyRuleConfigSchema);

const PolicyBaseFile = z.object({
  enabled: z.boolean().default(false),
  rules: RuleMapSchema.default({}),
});

const PermissionsClassificationSchema = z.object({
  classification: z.string(),
});

function buildPath(dirName: string) {
  return path.join(MOCK_DATA_BASE_PATH, 'audit-configs', dirName);
}

describe('file manager', () => {
  let TestAuditConfigShape: AuditConfigFileSchema;

  beforeEach(() => {
    TestAuditConfigShape = {
      classifications: {
        userPermissions: {
          schema: z.object({ permissions: z.record(z.string(), PermissionsClassificationSchema) }),
          entities: 'permissions',
        },
        profiles: {
          schema: z.object({
            profiles: z.record(
              z.string(),
              z.object({
                role: z.string(),
              })
            ),
          }),
        },
      },
      policies: {
        profiles: {
          schema: PolicyBaseFile,
        },
        permissionSets: {
          schema: PolicyBaseFile,
        },
        connectedApps: {
          schema: PolicyBaseFile,
        },
      },
    };
  });

  describe('parsing', () => {
    it('parses audit config from directory that matches shape', () => {
      // Act
      const fm = new FileManager(TestAuditConfigShape);
      const conf = fm.parse(buildPath('full-valid'));

      // Assert
      assert.isDefined(conf.classifications);
      assert.isDefined(conf.classifications.userPermissions);
      assert.isDefined(conf.classifications.profiles);
      assert.isDefined(conf.policies);
      assert.isDefined(conf.policies.profiles);
      assert.isDefined(conf.policies.permissionSets);
      assert.isDefined(conf.policies.connectedApps);
    });

    it('parses partial audit config from directory that matches shape', () => {
      // Act
      const fm = new FileManager(TestAuditConfigShape);
      const conf = fm.parse(buildPath('minimal'));

      // Assert
      assert.isDefined(conf.classifications);
      assert.isDefined(conf.classifications.userPermissions);
      assert.isDefined(conf.classifications.profiles);
      assert.isDefined(conf.policies);
      assert.isDefined(conf.policies.profiles);
      expect(conf.policies.connectedApps).to.be.undefined;
      expect(conf.policies.permissionSets).to.be.undefined;
    });

    it('throws error if config does not satisfy minimum criteria', () => {
      // Act
      const dirPath = buildPath('empty');
      const fm = new FileManager(TestAuditConfigShape);

      // Assert
      // assert against the message, not the complete error. Otherwise, stack will
      // always be different and assert will fail
      const expectedError = messages.getMessage('NoAuditConfigFound', [dirPath]);
      expect(() => fm.parse(dirPath)).to.throw(expectedError);
    });

    it('throws error is config does not satisfy configured dependencies', () => {
      // Arrange
      TestAuditConfigShape.policies.profiles.dependencies = [
        { path: ['classifications', 'userPermissions'], errorName: 'UserPermClassificationRequiredForProfiles' },
      ];
      const fm = new FileManager(TestAuditConfigShape);

      // Assert
      const expectedError = messages.getMessage('UserPermClassificationRequiredForProfiles');
      expect(() => fm.parse(buildPath('no-classifications'))).to.throw(expectedError);
    });

    it('parses config that satisfies all configured dependencies', () => {
      // Arrange
      TestAuditConfigShape.policies.profiles.dependencies = [
        { path: ['classifications', 'userPermissions'], errorName: 'UserPermClassificationRequiredForProfiles' },
      ];
      const fm = new FileManager(TestAuditConfigShape);

      // Act
      const conf = fm.parse(buildPath('full-valid'));

      // Assert
      assert.isDefined(conf.classifications);
      assert.isDefined(conf.classifications.userPermissions);
    });

    it('ignores policy-dependencies if policy is not present', () => {
      // Arrange
      TestAuditConfigShape.policies.profiles.dependencies = [
        { path: ['classifications', 'userPermissions'], errorName: 'UserPermClassificationRequiredForProfiles' },
      ];
      const fm = new FileManager(TestAuditConfigShape);

      // Act
      const conf = fm.parse(buildPath('no-classifications-2'));

      // Assert
      assert.isDefined(conf.classifications);
      assert.isDefined(conf.policies);
      assert.isDefined(conf.policies.permissionSets);
    });
  });

  describe('saving', () => {
    const DEFAULT_TEST_OUTPUT_DIR = path.join('tmp', 'test-outputs', 'audit-config');

    afterEach(() => {
      fs.rmSync(DEFAULT_TEST_OUTPUT_DIR, { recursive: true, force: true });
    });

    it('saves audit config that is compatible with shape', () => {
      // Act
      const fm = new FileManager(TestAuditConfigShape);
      const saveResult = fm.save(DEFAULT_TEST_OUTPUT_DIR, {
        classifications: {
          userPermissions: { permissions: { TestPermission: { classification: 'Unknown' } } },
        },
        policies: {
          profiles: { enabled: true, rules: { TestRule: { enabled: true } } },
          permissionSets: { enabled: true, rules: { TestRule: { enabled: true } } },
        },
      });

      // Assert
      const profilesPath = path.join(DEFAULT_TEST_OUTPUT_DIR, 'policies', 'profiles.yml');
      expect(saveResult.policies.profiles.filePath).to.equal(profilesPath);
      const permsetsPath = path.join(DEFAULT_TEST_OUTPUT_DIR, 'policies', 'permissionSets.yml');
      expect(saveResult.policies.permissionSets.filePath).to.equal(permsetsPath);
      const userClassPath = path.join(DEFAULT_TEST_OUTPUT_DIR, 'classifications', 'userPermissions.yml');
      expect(saveResult.classifications.userPermissions.filePath).to.equal(userClassPath);
      expect(saveResult.classifications.userPermissions.totalEntities).to.equal(1);
      expect(fs.existsSync(userClassPath)).to.be.true;
      expect(fs.existsSync(profilesPath)).to.be.true;
      expect(fs.existsSync(permsetsPath)).to.be.true;
    });

    it('ignores elements in audit config that are not present in shape', () => {
      // Act
      const fm = new FileManager(TestAuditConfigShape);
      const saveResult = fm.save(DEFAULT_TEST_OUTPUT_DIR, {
        policies: {
          someUnknownPolicy: { enabled: true, rules: { TestRule: { enabled: true } } },
          permissionSets: { enabled: true, rules: { TestRule: { enabled: true } } },
        },
      });

      // Assert
      expect(saveResult.policies.profiles).to.be.undefined;
      const permsetsPath = path.join(DEFAULT_TEST_OUTPUT_DIR, 'policies', 'permissionSets.yml');
      expect(saveResult.policies.permissionSets.filePath).to.equal(permsetsPath);
      expect(saveResult.policies.someUnknownPolicy).to.be.undefined;
      const potentialInvalidPath = path.join(DEFAULT_TEST_OUTPUT_DIR, 'policies', 'someUnknownPolicy.yml');
      expect(fs.existsSync(potentialInvalidPath)).to.be.false;
    });
  });
});
