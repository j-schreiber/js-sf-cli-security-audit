import fs from 'node:fs';
import path from 'node:path';
import z from 'zod';
import { assert, expect } from 'chai';
import { Messages } from '@salesforce/core';
import FileManager from '../../src/libs/audit-engine/file-manager/fileManager.js';
import {
  AuditConfigShapeDefinition,
  ConfigFileDependency,
} from '../../src/libs/audit-engine/file-manager/fileManager.types.js';
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

const allowedRiskSchema = z.object({ reason: z.string() });
const riskIdentifierMapping = z.record(z.string(), allowedRiskSchema);
const risksSchema = z.record(z.string(), z.union([riskIdentifierMapping, z.record(z.string(), riskIdentifierMapping)]));

function buildPath(dirName: string) {
  return path.join(MOCK_DATA_BASE_PATH, 'audit-configs', dirName);
}

/**
 * Shape must be defined "as const Shape", otherwise typescript
 * loosens the type too much and dynamic inference of schema types
 * does not work.
 */
const testShape = {
  classifications: {
    files: {
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
  },
  policies: {
    files: {
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
  },
} as const satisfies AuditConfigShapeDefinition;

describe('file manager', () => {
  describe('parsing', () => {
    it('parses audit config from directory that matches shape', () => {
      // Act
      const fm = new FileManager(testShape);
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
      const fm = new FileManager(testShape);
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
      const fm = new FileManager(testShape);

      // Assert
      // assert against the message, not the complete error. Otherwise, stack will
      // always be different and assert will fail
      const expectedError = messages.getMessage('NoAuditConfigFound', [dirPath]);
      expect(() => fm.parse(dirPath)).to.throw(expectedError);
    });

    it('throws error is config does not satisfy configured dependencies', () => {
      // Arrange
      const extendedShape = wrapProfileDependencies([
        {
          path: ['classifications', 'userPermissions'],
          errorName: 'UserPermClassificationRequiredForProfiles',
        },
      ]);
      const fm = new FileManager(extendedShape);

      // Assert
      const expectedError = messages.getMessage('UserPermClassificationRequiredForProfiles');
      expect(() => fm.parse(buildPath('no-classifications'))).to.throw(expectedError);
    });

    it('parses config that satisfies all configured dependencies', () => {
      // Arrange
      const extendedShape = wrapProfileDependencies([
        { path: ['classifications', 'userPermissions'], errorName: 'UserPermClassificationRequiredForProfiles' },
      ]);
      const fm = new FileManager(extendedShape);

      // Act
      const conf = fm.parse(buildPath('full-valid'));

      // Assert
      assert.isDefined(conf.classifications);
      assert.isDefined(conf.classifications.userPermissions);
    });

    it('ignores policy-dependencies if policy is not present', () => {
      // Arrange
      const extendedShape = wrapProfileDependencies([
        { path: ['classifications', 'userPermissions'], errorName: 'UserPermClassificationRequiredForProfiles' },
      ]);
      const fm = new FileManager(extendedShape);

      // Act
      const conf = fm.parse(buildPath('no-classifications-2'));

      // Assert
      assert.isDefined(conf.classifications);
      assert.isDefined(conf.policies);
      assert.isDefined(conf.policies.permissionSets);
    });

    it('reads accepted risks for mapped policies', () => {
      // Arrange
      const extendedShape = {
        classifications: testShape.classifications,
        policies: testShape.policies,
        acceptedRisks: {
          dirs: {
            profiles: {
              files: {
                EnforcePermissionClassifications: {
                  schema: risksSchema,
                },
                TestRule: {
                  schema: risksSchema,
                },
              },
            },
            users: {
              files: {
                NoStandardProfilesOnActiveUsers: {
                  schema: risksSchema,
                },
                NoOtherApexApiLogins: {
                  schema: risksSchema,
                },
                EnforcePermissionClassifications: {
                  schema: risksSchema,
                },
              },
            },
          },
        },
      };

      // Act
      const fm = new FileManager(extendedShape);
      const conf = fm.parse(buildPath('full-valid'));

      // Assert
      assert.isDefined(conf.acceptedRisks);
      assert.isDefined(conf.acceptedRisks.users);
      assert.isDefined(conf.acceptedRisks.users.NoStandardProfilesOnActiveUsers);
      assert.isDefined(conf.acceptedRisks.users.NoOtherApexApiLogins);
      assert.isDefined(conf.acceptedRisks.users.EnforcePermissionClassifications);
      assert.isDefined(conf.acceptedRisks.profiles);
      assert.isDefined(conf.acceptedRisks.profiles.EnforcePermissionClassifications);
      assert.isUndefined(conf.acceptedRisks.profiles.TestRule);
    });
  });

  describe('saving', () => {
    const DEFAULT_TEST_OUTPUT_DIR = path.join('tmp', 'test-outputs', 'audit-config');

    afterEach(() => {
      fs.rmSync(DEFAULT_TEST_OUTPUT_DIR, { recursive: true, force: true });
    });

    it('saves audit config that is compatible with shape', () => {
      // Act
      const fm = new FileManager(testShape);
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
      const fm = new FileManager(testShape);
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
      const potentialInvalidPath = path.join(DEFAULT_TEST_OUTPUT_DIR, 'policies', 'someUnknownPolicy.yml');
      expect(fs.existsSync(potentialInvalidPath)).to.be.false;
    });
  });
});

function wrapProfileDependencies(deps: ConfigFileDependency[]): AuditConfigShapeDefinition {
  return {
    classifications: testShape.classifications,
    policies: {
      files: {
        profiles: {
          ...testShape.policies.files.profiles,
          dependencies: deps,
        },
        permissionSets: {
          ...testShape.policies.files.permissionSets,
        },
      },
    },
  };
}
