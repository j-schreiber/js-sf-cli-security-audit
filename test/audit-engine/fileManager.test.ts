import fs from 'node:fs';
import path from 'node:path';
import z from 'zod';
import yaml from 'js-yaml';
import { assert, expect } from 'chai';
import { Messages } from '@salesforce/core';
import FileManager from '../../src/libs/audit-engine/file-manager/fileManager.js';
import {
  RefineError,
  AuditConfigShapeDefinition,
  ConfigFileDependency,
  ExtractAuditConfigTypes,
} from '../../src/libs/audit-engine/file-manager/fileManager.types.js';
import { MOCK_DATA_BASE_PATH } from '../mocks/data/paths.js';
import { AcceptedRisksSchema, RoleDefinitionsFileSchema } from '../../src/libs/audit-engine/registry/shape/schema.js';

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

/**
 * Shape must be defined "as const Shape", otherwise typescript
 * loosens the type too much and dynamic inference of schema types
 * does not work.
 */
const baseShape = {
  definitions: {
    files: {
      roles: { schema: RoleDefinitionsFileSchema },
    },
  },
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
      users: {
        schema: PolicyBaseFile,
      },
    },
  },
} as const satisfies AuditConfigShapeDefinition;

const extendedShape = {
  definitions: baseShape.definitions,
  classifications: baseShape.classifications,
  policies: baseShape.policies,
  acceptedRisks: {
    dirs: {
      profiles: {
        files: {
          EnforcePermissionClassifications: {
            schema: AcceptedRisksSchema,
          },
          TestRule: {
            schema: AcceptedRisksSchema,
          },
        },
      },
      users: {
        files: {
          NoStandardProfilesOnActiveUsers: {
            schema: AcceptedRisksSchema,
          },
          NoOtherApexApiLogins: {
            schema: AcceptedRisksSchema,
          },
          EnforcePermissionClassifications: {
            schema: AcceptedRisksSchema,
          },
          NoInactiveUsers: {
            schema: AcceptedRisksSchema,
          },
        },
      },
    },
  },
} satisfies AuditConfigShapeDefinition;

const validator = (parseResult: ExtractAuditConfigTypes<typeof baseShape>) => {
  const errors: RefineError[] = [];
  if (parseResult.definitions.roles && parseResult.classifications.profiles) {
    for (const [profileName, profile] of Object.entries(parseResult.classifications.profiles.profiles)) {
      if (!parseResult.definitions.roles[profile.role]) {
        errors.push({ message: `Invalid role ${profile.role} for profile`, path: ['profiles', profileName] });
      }
    }
  }
  if (!parseResult.policies || Object.keys(parseResult.policies).length === 0) {
    errors.push({
      message: 'Config invalid or empty. Needs one policy.',
      path: ['policies'],
    });
  }
  return errors;
};

describe('file manager', () => {
  describe('parsing', () => {
    it('parses audit config from directory that matches shape', () => {
      // Act
      const fm = new FileManager(baseShape);
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
      const fm = new FileManager(baseShape);
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
      const fm = new FileManager(baseShape, validator);

      // Assert
      // assert against the message, not the complete error. Otherwise, stack will
      // always be different and assert will fail
      const expectedError = messages.getMessage('error.FailedToValidateAuditConfig', [
        dirPath,
        'Config invalid or empty. Needs one policy.',
        'policies',
      ]);
      expect(() => fm.parse(dirPath)).to.throw(expectedError);
    });

    it('throws error is config does not satisfy configured dependencies', () => {
      // Arrange
      const wrappedBaseShape = wrapProfileDependencies([
        {
          path: ['classifications', 'userPermissions'],
          errorName: 'UserPermClassificationRequiredForProfiles',
        },
      ]);
      const fm = new FileManager(wrappedBaseShape);

      // Assert
      const expectedError = messages.getMessage('UserPermClassificationRequiredForProfiles');
      expect(() => fm.parse(buildPath('no-classifications'))).to.throw(expectedError);
    });

    it('parses config that satisfies all configured dependencies', () => {
      // Arrange
      const wrappedBaseShape = wrapProfileDependencies([
        { path: ['classifications', 'userPermissions'], errorName: 'UserPermClassificationRequiredForProfiles' },
      ]);
      const fm = new FileManager(wrappedBaseShape);

      // Act
      const conf = fm.parse(buildPath('full-valid'));

      // Assert
      assert.isDefined(conf.classifications);
      assert.isDefined(conf.classifications.userPermissions);
    });

    it('ignores policy-dependencies if policy is not present', () => {
      // Arrange
      const wrappedBaseShape = wrapProfileDependencies([
        { path: ['classifications', 'userPermissions'], errorName: 'UserPermClassificationRequiredForProfiles' },
      ]);
      const fm = new FileManager(wrappedBaseShape);

      // Act
      const conf = fm.parse(buildPath('no-classifications-2'));

      // Assert
      assert.isDefined(conf.classifications);
      assert.isDefined(conf.policies);
      assert.isDefined(conf.policies.permissionSets);
    });

    it('reads accepted risks for mapped policies', () => {
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

    it('parses accepted risks with deep and flat matchers', () => {
      // Act
      const fm = new FileManager(extendedShape);
      const conf = fm.parse(buildPath('edge-case-risks'));

      // Assert
      assert.isDefined(conf.acceptedRisks);
      assert.isDefined(conf.acceptedRisks.users);
      assert.isDefined(conf.acceptedRisks.users.EnforcePermissionClassifications);
      assert.isDefined(conf.acceptedRisks.users.NoInactiveUsers);
    });

    it('parses role definition from config file if it exists', () => {
      // Act
      const fm = new FileManager(baseShape, validator);
      const conf = fm.parse(buildPath('custom-roles'));

      // Assert
      assert.isDefined(conf.definitions.roles);
      expect(Object.keys(conf.definitions.roles)).to.deep.equal([
        'DeployEntity',
        'IntegrationUser',
        'Developer',
        'Ops',
        'Standard',
      ]);
      expect(conf.definitions.roles.DeployEntity.deniedPermissions).to.deep.equal(['ViewAllData', 'ModifyAllData']);
      assert.isDefined(conf.classifications.profiles);
      expect(conf.classifications.profiles.profiles['API Only Deploy'].role).to.equal('DeployEntity');
    });

    it('runs custom validation logic on profiles classification', () => {
      // Arrange
      const fm = new FileManager(baseShape, validator);

      // Assert
      expect(() => fm.parse(buildPath('custom-roles-invalid'))).to.throw('Invalid role Admin for profile');
    });
  });

  describe('saving', () => {
    const DEFAULT_TEST_OUTPUT_DIR = path.join('tmp', 'test-outputs', 'audit-config');

    afterEach(() => {
      fs.rmSync(DEFAULT_TEST_OUTPUT_DIR, { recursive: true, force: true });
    });

    it('saves audit config that is compatible with shape', () => {
      // Act
      const fm = new FileManager(baseShape);
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
      const fm = new FileManager(baseShape);
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

    it('saves accepted risks to disk', () => {
      // Arrange
      const testRuleContent = {
        'Profile Name': {
          'Second Ident': {
            reason: 'Testing',
          },
        },
      };

      const noApexLoginsContent = {
        'test@example.com': {
          '*': {
            reason: 'Logins for this dates are okay',
          },
        },
      };

      // Act
      const fm = new FileManager(extendedShape);
      const saveResult = fm.save(DEFAULT_TEST_OUTPUT_DIR, {
        acceptedRisks: {
          profiles: {
            TestRule: testRuleContent,
          },
          users: {
            NoOtherApexApiLogins: noApexLoginsContent,
          },
        },
      });

      // Assert
      const apexLoginsPath = saveResult.acceptedRisks.users.NoOtherApexApiLogins.filePath;
      expect(apexLoginsPath).to.equal(
        path.join(DEFAULT_TEST_OUTPUT_DIR, 'acceptedRisks', 'users', 'NoOtherApexApiLogins.yml')
      );
      expect(saveResult.acceptedRisks.users.NoOtherApexApiLogins.content).to.deep.equal(noApexLoginsContent);
      assertFileContentEquals(apexLoginsPath, noApexLoginsContent);

      const testRulePath = saveResult.acceptedRisks.profiles.TestRule.filePath;
      expect(testRulePath).to.equal(path.join(DEFAULT_TEST_OUTPUT_DIR, 'acceptedRisks', 'profiles', 'TestRule.yml'));
      expect(saveResult.acceptedRisks.profiles.TestRule.content).to.deep.equal(testRuleContent);
      assertFileContentEquals(testRulePath, testRuleContent);
    });

    it('saves existing role definitions to disk', () => {
      // Arrange
      const roleDefs = {
        Ops: {
          allowedPermissions: ['ApiEnabled', 'ViewSetup'],
          allowedClassifications: ['Critical'],
        },
        Standard: {
          allowedClassifications: ['Low'],
        },
      };

      // Act
      const fm = new FileManager(baseShape);
      const saveResult = fm.save(DEFAULT_TEST_OUTPUT_DIR, {
        definitions: {
          roles: roleDefs,
        },
      });

      // Assert
      const defsSaveResult = saveResult.definitions.roles;
      expect(defsSaveResult.filePath).to.equal(path.join(DEFAULT_TEST_OUTPUT_DIR, 'definitions', 'roles.yml'));
      assertFileContentEquals(defsSaveResult.filePath, roleDefs);
    });

    it('wipes existing role definitions on disk if none exist', () => {
      // Arrange
      const rolesPath = arrangeRoleDefinitions(
        { MyRole: { allowedPermissions: ['TestPerm'] } },
        DEFAULT_TEST_OUTPUT_DIR
      );

      // Act
      const fm = new FileManager(baseShape);
      const saveResult = fm.save(DEFAULT_TEST_OUTPUT_DIR, {
        definitions: {
          roles: undefined,
        },
      });

      // Assert
      const defsSaveResult = saveResult.definitions.roles;
      assert.isDefined(defsSaveResult);
      expect(defsSaveResult.content).to.be.undefined;
      expect(fs.existsSync(rolesPath)).to.be.false;
    });
  });
});

function wrapProfileDependencies(deps: ConfigFileDependency[]): AuditConfigShapeDefinition {
  return {
    classifications: baseShape.classifications,
    policies: {
      files: {
        profiles: {
          ...baseShape.policies.files.profiles,
          dependencies: deps,
        },
        permissionSets: {
          ...baseShape.policies.files.permissionSets,
        },
      },
    },
  };
}

function assertFileContentEquals(filePath: string, expectedContent: unknown) {
  expect(fs.existsSync(filePath)).to.be.true;
  const actualFileContent = fs.readFileSync(filePath, 'utf-8');
  const parsedContent = yaml.load(actualFileContent);
  expect(parsedContent).to.deep.equal(expectedContent);
}

function arrangeRoleDefinitions(roleContent: unknown, auditConfigDir: string): string {
  const rolesPath = path.join(auditConfigDir, 'definitions', 'roles.yml');
  fs.mkdirSync(path.join(auditConfigDir, 'definitions'), { recursive: true });
  fs.writeFileSync(rolesPath, yaml.dump(roleContent));
  return rolesPath;
}
